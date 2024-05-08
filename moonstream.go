package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"time"
)

type RegisteredContract struct {
	Id                string    `json:"id"`
	Blockchain        string    `json:"blockchain"`
	Address           string    `json:"address"`
	MetatxRequesterId string    `json:"metatx_requester_id"`
	Title             string    `json:"title"`
	Description       string    `json:"description"`
	ImageURI          string    `json:"image_uri"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
}

type CallRequest struct {
	Id                string      `json:"id"`
	ContractId        string      `json:"contract_id"`
	ContractAddress   string      `json:"contract_address"`
	MetatxRequesterId string      `json:"metatx_requester_id"`
	CallRequestType   string      `json:"call_request_type"`
	Caller            string      `json:"caller"`
	Method            string      `json:"method"`
	RequestId         string      `json:"request_id"`
	Parameters        interface{} `json:"parameters"`
	ExpiresAt         time.Time   `json:"expires_at"`
	CreatedAt         time.Time   `json:"created_at"`
	UpdateAt          time.Time   `json:"updated_at"`
}

type CallRequestSpecification struct {
	Caller     string      `json:"caller"`
	Method     string      `json:"method"`
	RequestId  string      `json:"request_id"`
	Parameters interface{} `json:"parameters"`
}

type CreateCallRequestsRequest struct {
	ContractID      string                     `json:"contract_id,omitempty"`
	ContractAddress string                     `json:"contract_address,omitempty"`
	TTLDays         int                        `json:"ttl_days"`
	Specifications  []CallRequestSpecification `json:"specifications"`
}

type DropperCallRequestParameters struct {
	DropId        string `json:"dropId"`
	BlockDeadline string `json:"blockDeadline"`
	Amount        string `json:"amount"`
	Signer        string `json:"signer"`
	Signature     string `json:"signature"`
}

type MoonstreamEngineAPIClient struct {
	BaseURL    string
	HTTPClient *http.Client
}

type CallRequestsCheck struct {
	ExistingRequests [][]string `json:"existing_requests"`
}

func InitMoonstreamEngineAPIClient() (*MoonstreamEngineAPIClient, error) {
	if MOONSTREAM_API_URL == "" {
		MOONSTREAM_API_URL = "https://api.moonstream.to"
	}
	if MOONSTREAM_API_TIMEOUT_SECONDS == "" {
		MOONSTREAM_API_TIMEOUT_SECONDS = "30"
	}
	timeoutSeconds, conversionErr := strconv.Atoi(MOONSTREAM_API_TIMEOUT_SECONDS)
	if conversionErr != nil {
		return nil, conversionErr
	}
	timeout := time.Duration(timeoutSeconds) * time.Second
	httpClient := http.Client{Timeout: timeout}

	return &MoonstreamEngineAPIClient{
		BaseURL:    MOONSTREAM_API_URL,
		HTTPClient: &httpClient,
	}, nil
}

func (client *MoonstreamEngineAPIClient) ListRegisteredContracts(accessToken, blockchain, address, contractType string, limit, offset int) ([]RegisteredContract, error) {
	var contracts []RegisteredContract

	request, requestCreationErr := http.NewRequest("GET", fmt.Sprintf("%s/metatx/contracts/", client.BaseURL), nil)
	if requestCreationErr != nil {
		return contracts, requestCreationErr
	}

	request.Header.Add("Authorization", fmt.Sprintf("Bearer %s", accessToken))
	request.Header.Add("Accept", "application/json")

	queryParameters := request.URL.Query()
	if blockchain != "" {
		queryParameters.Add("blockchain", blockchain)
	}
	if address != "" {
		queryParameters.Add("address", address)
	}
	if contractType != "" {
		queryParameters.Add("contract_type", contractType)
	}
	queryParameters.Add("limit", strconv.Itoa(limit))
	queryParameters.Add("offset", strconv.Itoa(offset))

	request.URL.RawQuery = queryParameters.Encode()

	response, responseErr := client.HTTPClient.Do(request)
	if responseErr != nil {
		return contracts, responseErr
	}
	defer response.Body.Close()

	responseBody, responseBodyErr := io.ReadAll(response.Body)

	if response.StatusCode < 200 || response.StatusCode >= 300 {
		if responseBodyErr != nil {
			return contracts, fmt.Errorf("unexpected status code: %d -- could not read response body: %s", response.StatusCode, responseBodyErr.Error())
		}
		responseBodyString := string(responseBody)
		return contracts, fmt.Errorf("unexpected status code: %d -- response body: %s", response.StatusCode, responseBodyString)
	}

	if responseBodyErr != nil {
		return contracts, fmt.Errorf("could not read response body: %s", responseBodyErr.Error())
	}

	unmarshalErr := json.Unmarshal(responseBody, &contracts)
	if unmarshalErr != nil {
		return contracts, fmt.Errorf("could not parse response body: %s", unmarshalErr.Error())
	}

	return contracts, nil
}

func (client *MoonstreamEngineAPIClient) ListCallRequests(accessToken, contractId, contractAddress, caller string, limit, offset int, showExpired bool) ([]CallRequest, error) {
	var callRequests []CallRequest

	if caller == "" {
		return callRequests, fmt.Errorf("you must specify caller when listing call requests")
	}

	request, requestCreationErr := http.NewRequest("GET", fmt.Sprintf("%s/metatx/requests", client.BaseURL), nil)
	if requestCreationErr != nil {
		return callRequests, requestCreationErr
	}

	request.Header.Add("Authorization", fmt.Sprintf("Bearer %s", accessToken))
	request.Header.Add("Accept", "application/json")

	queryParameters := request.URL.Query()
	if contractId != "" {
		queryParameters.Add("contract_id", contractId)
	}
	if contractAddress != "" {
		queryParameters.Add("contract_address", contractAddress)
	}
	queryParameters.Add("caller", caller)
	queryParameters.Add("limit", strconv.Itoa(limit))
	queryParameters.Add("offset", strconv.Itoa(offset))
	queryParameters.Add("show_expired", strconv.FormatBool(showExpired))

	request.URL.RawQuery = queryParameters.Encode()

	response, responseErr := client.HTTPClient.Do(request)
	if responseErr != nil {
		return callRequests, responseErr
	}
	defer response.Body.Close()

	responseBody, responseBodyErr := io.ReadAll(response.Body)

	if response.StatusCode < 200 || response.StatusCode >= 300 {
		if responseBodyErr != nil {
			return callRequests, fmt.Errorf("unexpected status code: %d -- could not read response body: %s", response.StatusCode, responseBodyErr.Error())
		}
		responseBodyString := string(responseBody)
		return callRequests, fmt.Errorf("unexpected status code: %d -- response body: %s", response.StatusCode, responseBodyString)
	}

	if responseBodyErr != nil {
		return callRequests, fmt.Errorf("could not read response body: %s", responseBodyErr.Error())
	}

	unmarshalErr := json.Unmarshal(responseBody, &callRequests)
	if unmarshalErr != nil {
		return callRequests, fmt.Errorf("could not parse response body: %s", unmarshalErr.Error())
	}

	return callRequests, nil
}

func (client *MoonstreamEngineAPIClient) checkCallRequests(accessToken string, contractId,
	contractAddress string, callRequests []CallRequestSpecification) (int, CallRequestsCheck, string) {
	var callRequestsCheck CallRequestsCheck

	requestBody := CreateCallRequestsRequest{
		Specifications: callRequests,
	}

	if contractId != "" {
		requestBody.ContractID = contractId
	}

	if contractAddress != "" {
		requestBody.ContractAddress = contractAddress
	}

	requestBodyBytes, requestBodyBytesErr := json.Marshal(requestBody)
	if requestBodyBytesErr != nil {
		log.Printf("Unable to prepare request body, error: %v", requestBodyBytesErr)
		return 0, callRequestsCheck, ""
	}

	request, requestCreationErr := http.NewRequest("GET", fmt.Sprintf("%s/metatx/requests/check", client.BaseURL), bytes.NewBuffer(requestBodyBytes))
	if requestCreationErr != nil {
		log.Printf("Unable to create request, error: %v", requestCreationErr)
		return 0, callRequestsCheck, ""
	}

	request.Header.Add("Authorization", fmt.Sprintf("Bearer %s", accessToken))
	request.Header.Add("Accept", "application/json")
	request.Header.Add("Content-Type", "application/json")

	response, responseErr := client.HTTPClient.Do(request)
	if responseErr != nil {
		log.Printf("Unable to do request, error: %v", responseErr)
		return 0, callRequestsCheck, ""
	}
	defer response.Body.Close()

	responseBody, responseBodyErr := io.ReadAll(response.Body)
	if responseBodyErr != nil {
		log.Printf("Unable to parse response body, error: %v", responseBodyErr)
		return response.StatusCode, callRequestsCheck, response.Status
	}

	if response.StatusCode != 200 {
		return response.StatusCode, callRequestsCheck, string(responseBody)
	}

	unmarshalErr := json.Unmarshal(responseBody, &callRequestsCheck)
	if unmarshalErr != nil {
		log.Printf("Could not parse response body, error: %s", unmarshalErr)
		return response.StatusCode, callRequestsCheck, response.Status
	}

	return response.StatusCode, callRequestsCheck, response.Status
}

// sendCallRequests sends a POST request to metatx API
func (client *MoonstreamEngineAPIClient) sendCallRequests(accessToken string, requestBodyBytes []byte) (int, string) {
	request, requestCreationErr := http.NewRequest("POST", fmt.Sprintf("%s/metatx/requests", client.BaseURL), bytes.NewBuffer(requestBodyBytes))
	if requestCreationErr != nil {
		log.Printf("Unable to create request, error: %v", requestCreationErr)
		return 0, ""
	}

	request.Header.Add("Authorization", fmt.Sprintf("Bearer %s", accessToken))
	request.Header.Add("Accept", "application/json")
	request.Header.Add("Content-Type", "application/json")

	response, responseErr := client.HTTPClient.Do(request)
	if responseErr != nil {
		log.Printf("Unable to do request, error: %v", responseErr)
		return 0, ""
	}
	defer response.Body.Close()

	responseBody, responseBodyErr := io.ReadAll(response.Body)
	if responseBodyErr != nil {
		log.Printf("Unable to parse response body, error: %v", responseBodyErr)
		return response.StatusCode, ""
	}

	return response.StatusCode, string(responseBody)
}
