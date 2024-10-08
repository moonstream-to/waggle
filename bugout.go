package main

// Much of this code is copied from waggle: https://github.com/bugout-dev/waggle/blob/main/main.go

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	bugout "github.com/bugout-dev/bugout-go/pkg"
	spire "github.com/bugout-dev/bugout-go/pkg/spire"
)

type BugoutAPIClient struct {
	BroodBaseURL string
	SpireBaseURL string
	HTTPClient   *http.Client

	BugoutSpireClient spire.SpireClient
}

func InitBugoutAPIClient() (*BugoutAPIClient, error) {
	if BROOD_API_URL == "" {
		BROOD_API_URL = "https://auth.bugout.dev"
	}
	if SPIRE_API_URL == "" {
		SPIRE_API_URL = "https://spire.bugout.dev"
	}
	if BUGOUT_API_TIMEOUT_SECONDS == "" {
		BUGOUT_API_TIMEOUT_SECONDS = "10"
	}
	timeoutSeconds, conversionErr := strconv.Atoi(BUGOUT_API_TIMEOUT_SECONDS)
	if conversionErr != nil {
		return nil, conversionErr
	}
	timeout := time.Duration(timeoutSeconds) * time.Second
	httpClient := http.Client{Timeout: timeout}

	spire.ClientFromEnv()

	return &BugoutAPIClient{
		BroodBaseURL: BROOD_API_URL,
		SpireBaseURL: SPIRE_API_URL,
		HTTPClient:   &httpClient,

		BugoutSpireClient: spire.SpireClient{SpireURL: SPIRE_API_URL, Routes: spire.RoutesFromURL(SPIRE_API_URL), HTTPClient: &httpClient},
	}, nil
}

func CleanTimestamp(rawTimestamp string) string {
	return strings.ReplaceAll(rawTimestamp, " ", "T")
}

func GetCursorFromJournal(client *bugout.BugoutClient, token, journalID, cursorName string) (string, error) {
	query := fmt.Sprintf("context_type:waggle tag:type:cursor tag:cursor:%s", cursorName)
	parameters := map[string]string{
		"order":   "desc",
		"content": "true", // We may use the content in the future, even though we are simply using context_url right now
	}
	results, err := client.Spire.SearchEntries(token, journalID, query, 1, 0, parameters)
	if err != nil {
		return "", err
	}

	if results.TotalResults == 0 {
		return "", nil
	}

	return results.Results[0].ContextUrl, nil
}

func WriteCursorToJournal(client *bugout.BugoutClient, token, journalID, cursorName, cursor, queryTerms string) error {
	title := fmt.Sprintf("waggle cursor: %s", cursorName)
	entryContext := spire.EntryContext{
		ContextType: "waggle",
		ContextID:   cursor,
		ContextURL:  cursor,
	}
	tags := []string{
		"type:cursor",
		fmt.Sprintf("cursor:%s", cursorName),
		fmt.Sprintf("waggle_version:%s", WAGGLE_VERSION),
	}
	content := fmt.Sprintf("Cursor: %s at %s\nQuery: %s", cursorName, cursor, queryTerms)
	_, err := client.Spire.CreateEntry(token, journalID, title, content, tags, entryContext)
	return err
}

func ReportsIterator(client *bugout.BugoutClient, token, journalID, cursor, queryTerms string, limit, offset int) (spire.EntryResultsPage, error) {
	var query string = fmt.Sprintf("!tag:type:cursor %s", queryTerms)
	if cursor != "" {
		cleanedCursor := CleanTimestamp(cursor)
		query = fmt.Sprintf("%s created_at:>%s", query, cleanedCursor)
		fmt.Fprintln(os.Stderr, "query:", query)
	}
	parameters := map[string]string{
		"order":   "asc",
		"content": "false",
	}
	return client.Spire.SearchEntries(token, journalID, query, limit, offset, parameters)
}

func LoadDropperReports(searchResults spire.EntryResultsPage) ([]DropperClaimMessage, error) {
	reports := make([]DropperClaimMessage, len(searchResults.Results))
	for i, result := range searchResults.Results {
		parseErr := json.Unmarshal([]byte(result.Content), &reports[i])
		if parseErr != nil {
			return reports, parseErr
		}
	}
	return reports, nil
}

func DropperReportsToCSV(reports []DropperClaimMessage, header bool, w io.Writer) error {
	numRecords := len(reports)
	startIndex := 0
	if header {
		numRecords++
		startIndex++
	}

	records := make([][]string, numRecords)
	if header {
		records[0] = []string{
			"dropId", "requestID", "claimant", "blockDeadline", "amount", "signer", "signature",
		}
	}

	for i, report := range reports {
		records[i+startIndex] = []string{
			report.DropId,
			report.RequestID,
			report.Claimant,
			report.BlockDeadline,
			report.Amount,
			report.Signer,
			report.Signature,
		}
	}

	csvWriter := csv.NewWriter(w)
	return csvWriter.WriteAll(records)
}

func ProcessDropperClaims(client *bugout.BugoutClient, bugoutToken, journalID, cursorName, query string, batchSize int, header bool, w io.Writer) error {
	cursor, cursorErr := GetCursorFromJournal(client, bugoutToken, journalID, cursorName)
	if cursorErr != nil {
		return cursorErr
	}

	searchResults, searchErr := ReportsIterator(client, bugoutToken, journalID, cursor, query, batchSize, 0)
	if searchErr != nil {
		return searchErr
	}

	reports, loadErr := LoadDropperReports(searchResults)
	if loadErr != nil {
		return loadErr
	}

	writeErr := DropperReportsToCSV(reports, header, w)
	if writeErr != nil {
		return writeErr
	}

	var processedErr error
	if len(searchResults.Results) > 0 {
		processedErr = WriteCursorToJournal(client, bugoutToken, journalID, cursorName, searchResults.Results[len(searchResults.Results)-1].CreatedAt, query)
	}

	return processedErr
}

type RequestResourceHolder struct {
	HolderId    string   `json:"holder_id"`
	HolderType  string   `json:"holder_type"`
	Permissions []string `json:"permissions"`
}

type ResourceHolder struct {
	Id          string   `json:"id"`
	HolderType  string   `json:"holder_type"`
	Permissions []string `json:"permissions"`
}

type ResourceHolderUser struct {
	Id            string   `json:"id"`
	Username      string   `json:"username"`
	ApplicationId string   `json:"application_id"`
	HolderType    string   `json:"holder_type"`
	Permissions   []string `json:"permissions"`
}

type ResourceHolderGroup struct {
	Id            string   `json:"id"`
	Name          string   `json:"name"`
	Autogenerated bool     `json:"autogenerated"`
	HolderType    string   `json:"holder_type"`
	Permissions   []string `json:"permissions"`
}

type ResourceHolders struct {
	ResourceId string           `json:"resource_id"`
	Holders    []ResourceHolder `json:"holders"`
}

func (c *BugoutAPIClient) CheckAccessToResource(token, resourceId string) (ResourceHolders, int, error) {
	var resourceHolders ResourceHolders

	var requestBodyBytes []byte
	request, requestErr := http.NewRequest("GET", fmt.Sprintf("%s/resources/%s/holders", c.BroodBaseURL, resourceId), bytes.NewBuffer(requestBodyBytes))
	if requestErr != nil {
		return resourceHolders, 0, requestErr
	}

	request.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
	request.Header.Add("Accept", "application/json")
	request.Header.Add("Content-Type", "application/json")

	response, responseErr := c.HTTPClient.Do(request)
	if responseErr != nil {
		return resourceHolders, 0, responseErr
	}
	defer response.Body.Close()

	responseBody, responseBodyErr := io.ReadAll(response.Body)
	if responseBodyErr != nil {
		return resourceHolders, response.StatusCode, fmt.Errorf("could not read response body: %s", responseBodyErr.Error())
	}

	if response.StatusCode != 200 {
		return resourceHolders, response.StatusCode, fmt.Errorf("unexpected status code: %d -- response status: %s", response.StatusCode, response.Status)
	}

	unmarshalErr := json.Unmarshal(responseBody, &resourceHolders)
	if unmarshalErr != nil {
		return resourceHolders, response.StatusCode, fmt.Errorf("could not parse response body: %s", unmarshalErr.Error())
	}

	return resourceHolders, response.StatusCode, nil
}

type User struct {
	Id            string `json:"user_id"`
	Username      string `json:"username"`
	ApplicationId string `json:"application_id"`
}

func (c *BugoutAPIClient) FindUser(token, userId string) (User, int, error) {
	var user User
	var requestBodyBytes []byte
	request, requestErr := http.NewRequest("GET", fmt.Sprintf("%s/user/find?user_id=%s", c.BroodBaseURL, userId), bytes.NewBuffer(requestBodyBytes))
	if requestErr != nil {
		return user, 0, requestErr
	}
	request.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
	request.Header.Add("Accept", "application/json")
	request.Header.Add("Content-Type", "application/json")

	response, responseErr := c.HTTPClient.Do(request)
	if responseErr != nil {
		return user, 0, requestErr
	}
	defer response.Body.Close()

	responseBody, responseBodyErr := io.ReadAll(response.Body)
	if responseBodyErr != nil {
		return user, response.StatusCode, fmt.Errorf("could not read response body: %s", responseBodyErr.Error())
	}

	if response.StatusCode != 200 {
		return user, response.StatusCode, fmt.Errorf("unexpected status code: %d -- response status: %s", response.StatusCode, response.Status)
	}

	unmarshalErr := json.Unmarshal(responseBody, &user)
	if unmarshalErr != nil {
		return user, response.StatusCode, fmt.Errorf("could not parse response body: %s", unmarshalErr.Error())
	}

	return user, response.StatusCode, nil
}

type Group struct {
	Id            string `json:"user_id"`
	Name          string `json:"name"`
	Autogenerated bool   `json:"autogenerated"`
}

func (c *BugoutAPIClient) FindGroup(token, groupId string) (Group, int, error) {
	var group Group
	var requestBodyBytes []byte
	request, requestErr := http.NewRequest("GET", fmt.Sprintf("%s/group/find?group_id=%s", c.BroodBaseURL, groupId), bytes.NewBuffer(requestBodyBytes))
	if requestErr != nil {
		return group, 0, requestErr
	}
	request.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
	request.Header.Add("Accept", "application/json")
	request.Header.Add("Content-Type", "application/json")

	response, responseErr := c.HTTPClient.Do(request)
	if responseErr != nil {
		return group, 0, requestErr
	}
	defer response.Body.Close()

	responseBody, responseBodyErr := io.ReadAll(response.Body)
	if responseBodyErr != nil {
		return group, response.StatusCode, fmt.Errorf("could not read response body: %s", responseBodyErr.Error())
	}

	if response.StatusCode != 200 {
		return group, response.StatusCode, fmt.Errorf("unexpected status code: %d -- response status: %s", response.StatusCode, response.Status)
	}

	unmarshalErr := json.Unmarshal(responseBody, &group)
	if unmarshalErr != nil {
		return group, response.StatusCode, fmt.Errorf("could not parse response body: %s", unmarshalErr.Error())
	}

	return group, response.StatusCode, nil
}

func (c *BugoutAPIClient) ModifyAccessToResource(token, resourceId, method string, requestResourceHolder *RequestResourceHolder) (ResourceHolders, int, error) {
	var resourceHolders ResourceHolders

	requestBody := RequestResourceHolder{
		HolderId:    requestResourceHolder.HolderId,
		HolderType:  requestResourceHolder.HolderType,
		Permissions: requestResourceHolder.Permissions,
	}
	reqBodyBytes := new(bytes.Buffer)
	json.NewEncoder(reqBodyBytes).Encode(requestBody)

	request, requestErr := http.NewRequest(method, fmt.Sprintf("%s/resources/%s/holders", c.BroodBaseURL, resourceId), reqBodyBytes)
	if requestErr != nil {
		return resourceHolders, 0, requestErr
	}

	request.Header.Add("Authorization", fmt.Sprintf("Bearer %s", token))
	request.Header.Add("Accept", "application/json")
	request.Header.Add("Content-Type", "application/json")

	response, responseErr := c.HTTPClient.Do(request)
	if responseErr != nil {
		return resourceHolders, 0, responseErr
	}
	defer response.Body.Close()

	responseBody, responseBodyErr := io.ReadAll(response.Body)
	if responseBodyErr != nil {
		return resourceHolders, response.StatusCode, fmt.Errorf("could not read response body: %s", responseBodyErr.Error())
	}

	if response.StatusCode != 200 {
		return resourceHolders, response.StatusCode, fmt.Errorf("unexpected status code: %d -- response status: %s", response.StatusCode, response.Status)
	}

	unmarshalErr := json.Unmarshal(responseBody, &resourceHolders)
	if unmarshalErr != nil {
		return resourceHolders, response.StatusCode, fmt.Errorf("could not parse response body: %s", unmarshalErr.Error())
	}

	return resourceHolders, response.StatusCode, nil
}

type JobEntryContent struct {
	FailedCallRequests   []string `json:"failed_call_requests"`
	PushedCallRequestIds []string `json:"pushed_call_request_ids"`

	ContentParseError bool   `json:"content_parse_error,omitempty"`
	ContentRaw        string `json:"content_raw,omitempty"`
}

type RequestJobEntry struct {
	Title   string   `json:"title"`
	Content string   `json:"content"`
	Tags    []string `json:"tags"`
}

type JobResponse struct {
	JobEntryUrl string          `json:"job_entry_url,omitempty"`
	Title       string          `json:"title"`
	Content     JobEntryContent `json:"content"`
	Tags        []string        `json:"tags"`
	CreatedAt   string          `json:"created_at"`
	UpdatedAt   string          `json:"updated_at"`
}

type JobsResponse struct {
	Signer       string        `json:"signer"`
	TotalResults int           `json:"total_results"`
	Offset       int           `json:"offset,omitempty"`
	NextOffset   int           `json:"next_offset,omitempty"`
	Jobs         []JobResponse `json:"jobs"`
}

func SearchJobsInJournal(client *spire.SpireClient, signer string, limit, offset int) (*JobsResponse, error) {
	searchQuery := fmt.Sprintf("tag:signer:%s", signer)
	parameters := map[string]string{
		"content": "true",
	}
	entryResultsPage, searchErr := client.SearchEntries(BUGOUT_WAGGLE_ADMIN_ACCESS_TOKEN, BUGOUT_METATX_JOBS_JOURNAL_ID, searchQuery, limit, offset, parameters)
	if searchErr != nil {
		return nil, searchErr
	}

	jobsResponse := JobsResponse{
		Signer:       signer,
		TotalResults: entryResultsPage.TotalResults,
		Offset:       entryResultsPage.Offset,
		NextOffset:   entryResultsPage.NextOffset,
	}

	for _, r := range entryResultsPage.Results {
		var jobEntryContent JobEntryContent
		unmarshalErr := json.Unmarshal([]byte(r.Content), &jobEntryContent)
		if unmarshalErr != nil {
			log.Printf("Unable to parse content for entry %s, error: %v", r.Url, unmarshalErr)
			jobEntryContent = JobEntryContent{
				ContentParseError: true,
				ContentRaw:        r.Content,
			}
		}

		job := JobResponse{
			JobEntryUrl: r.Url,
			Title:       r.Title,
			Content:     jobEntryContent,
			Tags:        r.Tags,
			CreatedAt:   r.CreatedAt,
			UpdatedAt:   r.UpdatedAt,
		}
		jobsResponse.Jobs = append(jobsResponse.Jobs, job)
	}

	return &jobsResponse, searchErr
}

func CreateJobInJournal(client *spire.SpireClient, signer string) (*spire.Entry, error) {
	title := fmt.Sprintf("draft job - signer %s", signer)
	entryContext := spire.EntryContext{
		ContextType: "waggle",
	}
	tags := []string{
		"type:job",
		fmt.Sprintf("signer:%s", signer),
		"complete:false",
	}
	content := string([]byte("{}"))
	jobEntry, err := client.CreateEntry(BUGOUT_WAGGLE_ADMIN_ACCESS_TOKEN, BUGOUT_METATX_JOBS_JOURNAL_ID, title, content, tags, entryContext)

	return &jobEntry, err
}

func (c *BugoutAPIClient) UpdateJobInJournal(entryId, signer string, pushedCallRequestIds, failedCallRequests []string) (int, error) {
	tags := []string{
		"type:job",
		fmt.Sprintf("signer:%s", signer),
		"complete:true",
	}
	if len(failedCallRequests) != 0 {
		tags = append(tags, "failed:true")
	}

	jobEntryContent := &JobEntryContent{
		FailedCallRequests:   failedCallRequests,
		PushedCallRequestIds: pushedCallRequestIds,
	}
	jobEntryContentStr, marshalErr := json.Marshal(jobEntryContent)
	if marshalErr != nil {
		return 0, marshalErr
	}

	requestBody := RequestJobEntry{
		Title:   fmt.Sprintf("job - signer %s", signer),
		Content: string(jobEntryContentStr),
		Tags:    tags,
	}
	reqBodyBytes := new(bytes.Buffer)
	json.NewEncoder(reqBodyBytes).Encode(requestBody)

	request, requestErr := http.NewRequest("PUT", fmt.Sprintf("%s/journals/%s/entries/%s?tags_action=replace", c.SpireBaseURL, BUGOUT_METATX_JOBS_JOURNAL_ID, entryId), reqBodyBytes)
	if requestErr != nil {
		return 0, requestErr
	}

	request.Header.Add("Authorization", fmt.Sprintf("Bearer %s", BUGOUT_WAGGLE_ADMIN_ACCESS_TOKEN))
	request.Header.Add("Accept", "application/json")
	request.Header.Add("Content-Type", "application/json")

	response, responseErr := c.HTTPClient.Do(request)
	if responseErr != nil {
		return 0, responseErr
	}
	defer response.Body.Close()

	return response.StatusCode, nil
}
