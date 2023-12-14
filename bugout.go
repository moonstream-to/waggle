package main

// Much of this code is copied from waggle: https://github.com/bugout-dev/waggle/blob/main/main.go

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
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

	return &BugoutAPIClient{
		BroodBaseURL: BROOD_API_URL,
		SpireBaseURL: SPIRE_API_URL,
		HTTPClient:   &httpClient,
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

type User struct {
	Id            string `json:"user_id"`
	Username      string `json:"username"`
	ApplicationId string `json:"application_id"`
}

func (c *BugoutAPIClient) GetUser(accessToken string) (User, error) {
	var user User
	var requestBodyBytes []byte
	request, requestErr := http.NewRequest("GET", fmt.Sprintf("%s/user", c.BroodBaseURL), bytes.NewBuffer(requestBodyBytes))
	if requestErr != nil {
		return user, requestErr
	}
	request.Header.Add("Authorization", fmt.Sprintf("Bearer %s", accessToken))
	request.Header.Add("Accept", "application/json")
	request.Header.Add("Content-Type", "application/json")

	response, responseErr := c.HTTPClient.Do(request)
	if responseErr != nil {
		return user, responseErr
	}
	defer response.Body.Close()

	responseBody, responseBodyErr := io.ReadAll(response.Body)

	if response.StatusCode < 200 || response.StatusCode >= 300 {
		if responseBodyErr != nil {
			return user, fmt.Errorf("unexpected status code: %d -- could not read response body: %s", response.StatusCode, responseBodyErr.Error())
		}
	}

	if responseBodyErr != nil {
		return user, fmt.Errorf("could not read response body: %s", responseBodyErr.Error())
	}

	unmarshalErr := json.Unmarshal(responseBody, &user)
	if unmarshalErr != nil {
		return user, fmt.Errorf("could not parse response body: %s", unmarshalErr.Error())
	}

	return user, nil
}

type AccessWaggleResourceData struct {
	Type        string `json:"type"`
	Customer    string `json:"customer"`
	AccessLevel string `json:"access_level"`
	UserId      string `json:"user_id"`
}

type AccessWaggleResource struct {
	Id            string                   `json:"id"`
	ApplicationId string                   `json:"application_id"`
	ResourceData  AccessWaggleResourceData `json:"resource_data"`
	CreatedAt     string                   `json:"created_at"`
	UpdatedAt     string                   `json:"updated_at"`
}

type AccessWaggleResources struct {
	Resources []AccessWaggleResource `json:"resources"`
}

func (c *BugoutAPIClient) GetAccessLevelFromResources() (AccessWaggleResources, error) {
	var accessWaggleResources AccessWaggleResources
	var requestBodyBytes []byte
	request, requestErr := http.NewRequest("GET", fmt.Sprintf("%s/resources", c.BroodBaseURL), bytes.NewBuffer(requestBodyBytes))
	if requestErr != nil {
		return accessWaggleResources, requestErr
	}
	queryParameters := request.URL.Query()
	queryParameters.Add("application_id", MOONSTREAM_APPLICATION_ID)
	queryParameters.Add("type", BUGOUT_RESOURCE_TYPE_WAGGLE_ACCESS)

	request.Header.Add("Authorization", fmt.Sprintf("Bearer %s", MOONSTREAM_WAGGLE_ADMIN_ACCESS_TOKEN))
	request.Header.Add("Accept", "application/json")
	request.Header.Add("Content-Type", "application/json")

	response, responseErr := c.HTTPClient.Do(request)
	if responseErr != nil {
		return accessWaggleResources, responseErr
	}
	defer response.Body.Close()

	responseBody, responseBodyErr := io.ReadAll(response.Body)

	if response.StatusCode < 200 || response.StatusCode >= 300 {
		if responseBodyErr != nil {
			return accessWaggleResources, fmt.Errorf("unexpected status code: %d -- could not read response body: %s", response.StatusCode, responseBodyErr.Error())
		}
	}

	if responseBodyErr != nil {
		return accessWaggleResources, fmt.Errorf("could not read response body: %s", responseBodyErr.Error())
	}

	unmarshalErr := json.Unmarshal(responseBody, &accessWaggleResources)
	if unmarshalErr != nil {
		return accessWaggleResources, fmt.Errorf("could not parse response body: %s", unmarshalErr.Error())
	}

	return accessWaggleResources, nil
}
