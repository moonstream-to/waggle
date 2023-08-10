package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
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
	AccessToken string
	BaseURL     string
	HTTPClient  *http.Client
}

func ClientFromEnv() (*MoonstreamEngineAPIClient, error) {
	if MOONSTREAM_ACCESS_TOKEN == "" {
		return nil, fmt.Errorf("set the MOONSTREAM_ACCESS_TOKEN environment variable")
	}
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
		AccessToken: MOONSTREAM_ACCESS_TOKEN,
		BaseURL:     MOONSTREAM_API_URL,
		HTTPClient:  &httpClient,
	}, nil
}

func (client *MoonstreamEngineAPIClient) ListRegisteredContracts(blockchain, address, contractType string, limit, offset int) ([]RegisteredContract, error) {
	var contracts []RegisteredContract

	request, requestCreationErr := http.NewRequest("GET", fmt.Sprintf("%s/metatx/contracts/", client.BaseURL), nil)
	if requestCreationErr != nil {
		return contracts, requestCreationErr
	}

	request.Header.Add("Authorization", fmt.Sprintf("Bearer %s", client.AccessToken))
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

func (client *MoonstreamEngineAPIClient) ListCallRequests(contractId, contractAddress, caller string, limit, offset int, showExpired bool) ([]CallRequest, error) {
	var callRequests []CallRequest

	if caller == "" {
		return callRequests, fmt.Errorf("you must specify caller when listing call requests")
	}

	request, requestCreationErr := http.NewRequest("GET", fmt.Sprintf("%s/metatx/requests", client.BaseURL), nil)
	if requestCreationErr != nil {
		return callRequests, requestCreationErr
	}

	request.Header.Add("Authorization", fmt.Sprintf("Bearer %s", client.AccessToken))
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

// sendCallRequests sends a POST request to metatx API
func (client *MoonstreamEngineAPIClient) sendCallRequests(requestBodyBytes []byte) error {
	request, requestCreationErr := http.NewRequest("POST", fmt.Sprintf("%s/metatx/requests", client.BaseURL), bytes.NewBuffer(requestBodyBytes))
	if requestCreationErr != nil {
		return requestCreationErr
	}

	request.Header.Add("Authorization", fmt.Sprintf("Bearer %s", client.AccessToken))
	request.Header.Add("Accept", "application/json")
	request.Header.Add("Content-Type", "application/json")

	response, responseErr := client.HTTPClient.Do(request)
	if responseErr != nil {
		return responseErr
	}
	defer response.Body.Close()

	responseBody, responseBodyErr := io.ReadAll(response.Body)

	if response.StatusCode < 200 || response.StatusCode >= 300 {
		if responseBodyErr != nil {
			return fmt.Errorf("unexpected status code: %d -- could not read response body: %s", response.StatusCode, responseBodyErr.Error())
		}
		responseBodyString := string(responseBody)
		return fmt.Errorf("unexpected status code: %d -- response body: %s", response.StatusCode, responseBodyString)
	}

	return nil
}

func (client *MoonstreamEngineAPIClient) CreateCallRequests(contractId, contractAddress string, ttlDays int, specs []CallRequestSpecification, batchSize int) error {
	if contractId == "" && contractAddress == "" {
		return fmt.Errorf("you must specify at least one of contractId or contractAddress when creating call requests")
	}

	var specBatches [][]CallRequestSpecification
	for i := 0; i <= len(specs); i += batchSize {
		if i+batchSize > len(specs) {
			specBatches = append(specBatches, specs[i:])
			break
		}
		specBatches = append(specBatches, specs[i:i+batchSize])
	}

	for i, batchSpecs := range specBatches {
		requestBody := CreateCallRequestsRequest{
			TTLDays:        ttlDays,
			Specifications: batchSpecs,
		}

		if contractId != "" {
			requestBody.ContractID = contractId
		}

		if contractAddress != "" {
			requestBody.ContractAddress = contractAddress
		}

		requestBodyBytes, requestBodyBytesErr := json.Marshal(requestBody)
		if requestBodyBytesErr != nil {
			return requestBodyBytesErr
		}

		sendReTryCnt := 1
		maxSendReTryCnt := 3
	SEND_RETRY:
		for sendReTryCnt <= maxSendReTryCnt {
			sendCallRequestsErr := client.sendCallRequests(requestBodyBytes)
			if sendCallRequestsErr == nil {
				break SEND_RETRY
			}
			fmt.Printf("During sending call requests an error ocurred: %v, retry %d\n", sendCallRequestsErr, sendReTryCnt)
			sendReTryCnt++
			time.Sleep(time.Duration(sendReTryCnt) * time.Second)

			if sendReTryCnt > maxSendReTryCnt {
				return fmt.Errorf("failed to send call requests")
			}
		}

		fmt.Printf("Successfully pushed %d batch of %d total with %d call_requests to API\n", i+1, len(specBatches), len(batchSpecs))
	}

	return nil
}
