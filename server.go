package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	spire "github.com/bugout-dev/bugout-go/pkg/spire"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/common"
	"github.com/google/uuid"
)

type AvailableSigner struct {
	key *keystore.Key
}

type Server struct {
	Host                      string
	Port                      int
	AccessResourceId          string
	AvailableSigners          map[string]AvailableSigner
	LogLevel                  int
	CORSWhitelist             map[string]bool
	BugoutAPIClient           *BugoutAPIClient
	MoonstreamEngineAPIClient *MoonstreamEngineAPIClient

	ServerMu sync.Mutex
	ServerWg sync.WaitGroup
}

type PingResponse struct {
	Status string `json:"status"`
}

type VersionResponse struct {
	Version string `json:"version"`
}

type SignersResponse struct {
	Signers []string `json:"signers"`
}

type SignDropperRequest struct {
	ChainId              int64                  `json:"chain_id"`
	Dropper              string                 `json:"dropper"`
	RegisteredContractId string                 `json:"registered_contract_id"`
	TtlDays              int                    `json:"ttl_days"`
	Sensible             bool                   `json:"sensible"`
	Requests             []*DropperClaimMessage `json:"requests"`

	NoMetatx      bool `json:"no_metatx"`
	NoCheckMetatx bool `json:"no_check_metatx"`
}

type SignDropperResponse struct {
	ChainId  int64                  `json:"chain_id"`
	Dropper  string                 `json:"dropper"`
	TtlDays  int                    `json:"ttl_days"`
	Sensible bool                   `json:"sensible"`
	Requests []*DropperClaimMessage `json:"requests"`

	MetatxRegistered bool   `json:"metatx_registered"`
	JobEntryId       string `json:"job_entry_id,omitempty"`
	JobEntryUrl      string `json:"job_entry_url,omitempty"`
}

type AccessLevel struct {
	Admin             bool
	RequestSignatures bool
}

type AuthorizationContext struct {
	AuthorizationToken    string
	AccessResourceHolders ResourceHolders
}

// Check access id was provided correctly and save user access configuration to request context
func (server *Server) accessMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract Authorization token if Bearer header provided
		var authorizationTokenRaw string
		authorizationTokenHeaders := r.Header[CASER.String("authorization")]
		for _, h := range authorizationTokenHeaders {
			authorizationTokenRaw = h
		}
		var authorizationToken string
		if authorizationTokenRaw == "" {
			http.Error(w, "No authorization header passed with request", http.StatusForbidden)
			return
		}

		authorizationTokenSlice := strings.Split(authorizationTokenRaw, " ")
		if len(authorizationTokenSlice) != 2 || authorizationTokenSlice[0] != "Bearer" || authorizationTokenSlice[1] == "" {
			http.Error(w, "Wrong authorization token provided", http.StatusForbidden)
			return
		}
		authorizationToken = authorizationTokenSlice[1]
		_, uuidParseErr := uuid.Parse(authorizationToken)
		if uuidParseErr != nil {
			http.Error(w, "Wrong authorization token provided", http.StatusForbidden)
			return
		}

		accessResourceHolders, statusCode, checkAccessErr := server.BugoutAPIClient.CheckAccessToResource(authorizationToken, server.AccessResourceId)
		if checkAccessErr != nil {
			switch statusCode {
			case 404:
				http.Error(w, "Not Found", http.StatusNotFound)
			case 400, 401, 403:
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
			default:
				http.Error(w, "Internal server error", http.StatusInternalServerError)
			}
			return
		}

		if len(accessResourceHolders.Holders) < 1 {
			http.Error(w, "Access restricted", http.StatusForbidden)
			return
		}

		authorizationContext := AuthorizationContext{
			AuthorizationToken:    authorizationToken,
			AccessResourceHolders: accessResourceHolders,
		}

		ctxUser := context.WithValue(r.Context(), "authorizationContext", authorizationContext)

		next.ServeHTTP(w, r.WithContext(ctxUser))
	})
}

// CORS middleware
func (server *Server) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var allowedOrigin string
		if server.CORSWhitelist["*"] {
			allowedOrigin = "*"
		} else {
			origin := r.Header.Get("Origin")
			if _, ok := server.CORSWhitelist[origin]; ok {
				allowedOrigin = origin
			}
		}

		if allowedOrigin != "" {
			w.Header().Set("Access-Control-Allow-Origin", allowedOrigin)
			w.Header().Set("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
			// Credentials are cookies, authorization headers, or TLS client certificates
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		}

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// Log access requests in proper format
func (server *Server) logMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, readErr := io.ReadAll(r.Body)
		if readErr != nil {
			http.Error(w, "Unable to read body", http.StatusBadRequest)
			return
		}
		r.Body = io.NopCloser(bytes.NewBuffer(body))
		if len(body) > 0 {
			defer r.Body.Close()
		}

		next.ServeHTTP(w, r)

		var ip string
		var splitErr error
		realIp := r.Header["X-Real-Ip"]
		if len(realIp) == 0 {
			ip, _, splitErr = net.SplitHostPort(r.RemoteAddr)
			if splitErr != nil {
				http.Error(w, fmt.Sprintf("Unable to parse client IP: %s", r.RemoteAddr), http.StatusBadRequest)
				return
			}
		} else {
			ip = realIp[0]
		}
		logStr := fmt.Sprintf("%s %s %s", ip, r.Method, r.URL.Path)

		if server.LogLevel >= 2 {
			if r.URL.RawQuery != "" {
				logStr += fmt.Sprintf(" %s", r.URL.RawQuery)
			}
		}
		log.Printf("%s\n", logStr)
	})
}

// Handle panic errors to prevent server shutdown
func (server *Server) panicMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if recoverErr := recover(); recoverErr != nil {
				log.Println("recovered", recoverErr)
				http.Error(w, "Internal server error", 500)
			}
		}()

		// There will be a defer with panic handler in each next function
		next.ServeHTTP(w, r)
	})
}

// pingRoute returns status of waggle server itself
func (server *Server) pingRoute(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	response := PingResponse{Status: "ok"}
	json.NewEncoder(w).Encode(response)
}

func (server *Server) versionRoute(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	response := VersionResponse{Version: WAGGLE_VERSION}
	json.NewEncoder(w).Encode(response)
}

func (server *Server) holdersHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		server.holdersRoute(w, r)
		return
	case http.MethodPost:
		server.modifyHolderAccessRoute(w, r, "POST")
		return
	case http.MethodDelete:
		server.modifyHolderAccessRoute(w, r, "DELETE")
		return
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
}

func (server *Server) holdersRoute(w http.ResponseWriter, r *http.Request) {
	authorizationContext := r.Context().Value("authorizationContext").(AuthorizationContext)
	accessResourceHolders := authorizationContext.AccessResourceHolders
	authorizationToken := authorizationContext.AuthorizationToken

	var holders []interface{}
	maxRequests := 4
	holdersLen := len(accessResourceHolders.Holders)

	sem := make(chan struct{}, 3)
	var wg sync.WaitGroup

	// Extend holders with names and additional data
	for i, h := range accessResourceHolders.Holders {
		wg.Add(1)
		go func(wg *sync.WaitGroup, sem chan struct{}, h ResourceHolder) {
			defer wg.Done()
			sem <- struct{}{}

			if h.HolderType == "user" {
				user, statusCode, userErr := server.BugoutAPIClient.FindUser(authorizationToken, h.Id)
				if userErr != nil {
					log.Println(statusCode, userErr)
					holders = append(holders, h)
				} else {
					rhUser := ResourceHolderUser{
						Id:            h.Id,
						Username:      user.Username,
						ApplicationId: user.ApplicationId,
						HolderType:    h.HolderType,
						Permissions:   h.Permissions,
					}
					holders = append(holders, rhUser)
				}
			} else if h.HolderType == "group" {
				group, statusCode, groupErr := server.BugoutAPIClient.FindGroup(authorizationToken, h.Id)
				if groupErr != nil {
					log.Println(statusCode, groupErr)
					holders = append(holders, h)
				} else {
					rhGroup := ResourceHolderGroup{
						Id:            h.Id,
						Name:          group.Name,
						Autogenerated: group.Autogenerated,
						HolderType:    h.HolderType,
						Permissions:   h.Permissions,
					}
					holders = append(holders, rhGroup)
				}
			} else {
				log.Printf("Unexpected holder type: %s\n", h.HolderType)
				holders = append(holders, h)
			}
			<-sem
		}(&wg, sem, h)

		if (i+1)%maxRequests == 0 && i+1 != holdersLen+1 {
			time.Sleep(50 * time.Millisecond)
		}
	}
	wg.Wait()
	close(sem)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(holders)
}

func (server *Server) modifyHolderAccessRoute(w http.ResponseWriter, r *http.Request, method string) {
	authorizationContext := r.Context().Value("authorizationContext").(AuthorizationContext)
	authorizationToken := authorizationContext.AuthorizationToken

	body, readErr := io.ReadAll(r.Body)
	if readErr != nil {
		http.Error(w, "Unable to read body", http.StatusBadRequest)
		return
	}
	r.Body = io.NopCloser(bytes.NewBuffer(body))
	if len(body) > 0 {
		defer r.Body.Close()
	}
	var req *RequestResourceHolder
	parseErr := json.Unmarshal(body, &req)
	if parseErr != nil {
		http.Error(w, "Unable to parse body", http.StatusBadRequest)
	}

	accessResourceHolders, statusCode, checkAccessErr := server.BugoutAPIClient.ModifyAccessToResource(authorizationToken, server.AccessResourceId, method, req)
	if checkAccessErr != nil {
		log.Println(statusCode, checkAccessErr)
		switch statusCode {
		case 404:
			http.Error(w, "Not Found", http.StatusNotFound)
		case 400, 401, 403:
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
		default:
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(accessResourceHolders.Holders)
}

func (server *Server) signersHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet && r.URL.Path == "/signers/" {
		server.signersRoute(w, r)
		return
	}

	routePathSlice := strings.Split(r.URL.Path, "/")
	requestedSigner := common.HexToAddress(routePathSlice[2]).String()
	_, ok := server.AvailableSigners[requestedSigner]
	if !ok {
		http.Error(w, fmt.Sprintf("Unacceptable signer provided %s", requestedSigner), http.StatusBadRequest)
		return
	}
	switch r.Method {
	case http.MethodGet:
		switch {
		case strings.Contains(r.URL.Path, "/jobs"):
			server.jobsRoute(w, r, requestedSigner)
			return
		default:
			http.Error(w, "Not found", http.StatusNotFound)
			return
		}
	case http.MethodPost:
		switch {
		case strings.Contains(r.URL.Path, "/dropper/sign"):
			// TODO: (kompotkot): Re-write in subroutes and subapps when times come
			server.signDropperRoute(w, r, requestedSigner)
			return
		case strings.Contains(r.URL.Path, "/dropperV3/sign"):
			server.signDropperV3Route(w, r, requestedSigner)
		default:
			http.Error(w, "Not found", http.StatusNotFound)
			return
		}
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
}

func (server *Server) signersRoute(w http.ResponseWriter, r *http.Request) {
	signers := make([]string, len(server.AvailableSigners))
	i := 0
	for s := range server.AvailableSigners {
		signers[i] = s
		i++
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(SignersResponse{
		Signers: signers,
	})
}

func (server *Server) jobsRoute(w http.ResponseWriter, r *http.Request, signer string) {
	limit := 10
	offset := 0
	queryIntParams := []string{"limit", "offset"}
	for _, qp := range queryIntParams {
		qpRaw := r.URL.Query().Get(qp)
		if qpRaw != "" {
			qpVal, err := strconv.Atoi(qpRaw)
			if err != nil {
				http.Error(w, fmt.Sprintf("Unable to parse %s as integer", qp), http.StatusBadRequest)
				return
			}
			switch qp {
			case "limit":
				limit = qpVal
			case "offset":
				offset = qpVal
			}
		}
	}

	jobs, searchErr := SearchJobsInJournal(&server.BugoutAPIClient.BugoutSpireClient, signer, limit, offset)
	if searchErr != nil {
		http.Error(w, searchErr.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(jobs)
}

// signDropperRoute sign dropper call requests
// If the query metatx is set to strict, then an error will be raised at the checkCallRequests step. If the metatx is soft (which is the default), then requests minus existing requests from checkCallRequests will be pushed.
func (server *Server) signDropperRoute(w http.ResponseWriter, r *http.Request, signer string) {
	authorizationContext := r.Context().Value("authorizationContext").(AuthorizationContext)
	authorizationToken := authorizationContext.AuthorizationToken

	body, readErr := io.ReadAll(r.Body)
	if readErr != nil {
		http.Error(w, "Unable to read body", http.StatusBadRequest)
		return
	}
	r.Body = io.NopCloser(bytes.NewBuffer(body))
	if len(body) > 0 {
		defer r.Body.Close()
	}
	var req *SignDropperRequest
	parseErr := json.Unmarshal(body, &req)
	if parseErr != nil {
		http.Error(w, "Unable to parse body", http.StatusBadRequest)
		return
	}

	if req.Dropper == "" && req.RegisteredContractId == "" {
		http.Error(w, "Dropper address or registered contract ID should be specified", http.StatusBadRequest)
		return
	}

	if req.RegisteredContractId != "" {
		contractStatusCode, registeredContract, contractStatus := server.MoonstreamEngineAPIClient.GetRegisteredContract(authorizationToken, req.RegisteredContractId)
		if contractStatusCode == 500 {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		if contractStatusCode != 200 {
			http.Error(w, contractStatus, contractStatusCode)
			return
		}

		req.ChainId = registeredContract.ChainId
		req.Dropper = registeredContract.Address
	}

	batchSize := 100
	callRequestsLen := len(req.Requests)

	var currentBatch []CallRequestSpecification
	var callRequestBatches [][]CallRequestSpecification

	var callRequestSpecifications []CallRequestSpecification

	for i, message := range req.Requests {
		messageHash, hashErr := DropperClaimMessageHash(req.ChainId, req.Dropper, message.DropId, message.RequestID, message.Claimant, message.BlockDeadline, message.Amount)
		if hashErr != nil {
			http.Error(w, "Unable to generate message hash", http.StatusInternalServerError)
			return
		}

		signedMessage, signatureErr := SignRawMessage(messageHash, server.AvailableSigners[signer].key, req.Sensible)
		if signatureErr != nil {
			http.Error(w, "Unable to sign message", http.StatusInternalServerError)
			return
		}

		message.Signature = hex.EncodeToString(signedMessage)
		message.Signer = server.AvailableSigners[signer].key.Address.Hex()

		if !req.NoMetatx {
			// If no_metatx key not provided with request, prepare slices for push to metatx call requests creation endpoint
			newCallRequest := CallRequestSpecification{
				Caller:    message.Claimant,
				Method:    "claim",
				RequestId: message.RequestID,
				Parameters: DropperCallRequestParameters{
					DropId:        message.DropId,
					BlockDeadline: message.BlockDeadline,
					Amount:        message.Amount,
					Signer:        signer,
					Signature:     message.Signature,
				},
			}
			callRequestSpecifications = append(callRequestSpecifications, newCallRequest)
			currentBatch = append(currentBatch, newCallRequest)
			if (i+1)%batchSize == 0 || i == callRequestsLen-1 {
				if currentBatch != nil {
					callRequestBatches = append(callRequestBatches, currentBatch)
				}
				currentBatch = nil // Reset the batch
			}
		}
	}

	// Run check of existing call_requests in database
	if !req.NoMetatx && !req.NoCheckMetatx {
		checkStatusCode, existingRequests, checkStatus := server.MoonstreamEngineAPIClient.checkCallRequests(authorizationToken, req.RegisteredContractId, req.Dropper, callRequestSpecifications)

		if checkStatusCode == 0 {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		} else if checkStatusCode == 200 {
			if len(existingRequests.ExistingRequests) != 0 {
				var existingReqIds string
				for i, r := range existingRequests.ExistingRequests {
					if i == 0 {
						existingReqIds += r[1]
						continue
					}
					existingReqIds += fmt.Sprintf(",%s", r[1])
				}
				http.Error(w, fmt.Sprintf("Conflicting records were found in the database: [%s]", existingReqIds), http.StatusConflict)
				return
			}
		} else {
			http.Error(w, checkStatus, checkStatusCode)
			return
		}
	}

	resp := SignDropperResponse{
		ChainId:  req.ChainId,
		Dropper:  req.Dropper,
		TtlDays:  req.TtlDays,
		Sensible: req.Sensible,
		Requests: req.Requests,
	}

	var jobEntry *spire.Entry
	// Prepare job entry for report
	if !req.NoMetatx {
		resp.MetatxRegistered = true

		var createJobErr error
		jobEntry, createJobErr = CreateJobInJournal(&server.BugoutAPIClient.BugoutSpireClient, signer)
		if createJobErr != nil {
			log.Printf("Unable to create job entry in journal, error: %v", createJobErr)
		}
	}

	if jobEntry != nil {
		resp.JobEntryId = jobEntry.Id
		resp.JobEntryUrl = fmt.Sprintf("%s/journals/%s/entries/%s", server.BugoutAPIClient.SpireBaseURL, BUGOUT_METATX_JOBS_JOURNAL_ID, jobEntry.Id)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)

	if !req.NoMetatx {
		pushedCallRequestIds := []string{}
		failedCallRequestIds := []string{}

		// Push batch by batch to metatx call requests creation endpoint in background
		go func() {
			for i, batchSpecs := range callRequestBatches {
				requestBody := CreateCallRequestsRequest{
					TTLDays:        req.TtlDays,
					Specifications: batchSpecs,
				}
				if req.RegisteredContractId != "" {
					requestBody.ContractID = req.RegisteredContractId
				} else {
					requestBody.ContractAddress = req.Dropper
				}

				requestBodyBytes, requestBodyBytesErr := json.Marshal(requestBody)
				if requestBodyBytesErr != nil {
					log.Printf("Unable to marshal body, error: %v", requestBodyBytesErr)
					for _, r := range batchSpecs {
						failedCallRequestIds = append(failedCallRequestIds, r.RequestId)
					}
					continue
				}

				statusCode, responseBodyStr := server.MoonstreamEngineAPIClient.sendCallRequests(authorizationToken, requestBodyBytes)
				if statusCode == 200 {
					for _, r := range batchSpecs {
						pushedCallRequestIds = append(pushedCallRequestIds, r.RequestId)
					}
					log.Printf("Batch %d of %d total with %d call_requests successfully pushed to API", i+1, len(callRequestBatches), callRequestsLen)
					continue
				}

				if statusCode == 409 {
					log.Printf("Batch %d of %d total with %d call_requests failed with duplication error: %v", i+1, len(callRequestBatches), callRequestsLen, responseBodyStr)
				} else {
					log.Printf("Batch %d of %d total with %d call_requests failed with error: %v", i+1, len(callRequestBatches), callRequestsLen, responseBodyStr)
				}
				for _, r := range batchSpecs {
					failedCallRequestIds = append(failedCallRequestIds, r.RequestId)
				}
			}

			// Send job report to entry
			if jobEntry != nil {
				jobStatusCode, writeJobErr := server.BugoutAPIClient.UpdateJobInJournal(jobEntry.Id, signer, pushedCallRequestIds, failedCallRequestIds)
				if writeJobErr != nil {
					log.Printf("Unable to push waggle job to journal, status code %d, error: %v", jobStatusCode, writeJobErr)
				}
			} else {
				log.Printf("Job entry creation failed, job report not pushed")
			}
		}()
	}
}

// signDropperV3Route sign dropperV3 call requests
// If the query metatx is set to strict, then an error will be raised at the checkCallRequests step. If the metatx is soft (which is the default), then requests minus existing requests from checkCallRequests will be pushed.
func (server *Server) signDropperV3Route(w http.ResponseWriter, r *http.Request, signer string) {
	authorizationContext := r.Context().Value("authorizationContext").(AuthorizationContext)
	authorizationToken := authorizationContext.AuthorizationToken

	body, readErr := io.ReadAll(r.Body)
	if readErr != nil {
		http.Error(w, "Unable to read body", http.StatusBadRequest)
		return
	}
	r.Body = io.NopCloser(bytes.NewBuffer(body))
	if len(body) > 0 {
		defer r.Body.Close()
	}
	var req *SignDropperRequest
	parseErr := json.Unmarshal(body, &req)
	if parseErr != nil {
		http.Error(w, "Unable to parse body", http.StatusBadRequest)
		return
	}

	if req.Dropper == "" && req.RegisteredContractId == "" {
		http.Error(w, "Dropper address or registered contract ID should be specified", http.StatusBadRequest)
		return
	}

	if req.RegisteredContractId != "" {
		contractStatusCode, registeredContract, contractStatus := server.MoonstreamEngineAPIClient.GetRegisteredContract(authorizationToken, req.RegisteredContractId)
		if contractStatusCode == 500 {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		if contractStatusCode != 200 {
			http.Error(w, contractStatus, contractStatusCode)
			return
		}

		req.ChainId = registeredContract.ChainId
		req.Dropper = registeredContract.Address
	}

	batchSize := 100
	callRequestsLen := len(req.Requests)

	var currentBatch []CallRequestSpecification
	var callRequestBatches [][]CallRequestSpecification

	var callRequestSpecifications []CallRequestSpecification

	for i, message := range req.Requests {
		messageHash, hashErr := DropperV3ClaimMessageHash(req.ChainId, req.Dropper, message.DropId, message.RequestID, message.Claimant, message.BlockDeadline, message.Amount)
		if hashErr != nil {
			http.Error(w, "Unable to generate message hash", http.StatusInternalServerError)
			return
		}

		signedMessage, signatureErr := SignRawMessage(messageHash, server.AvailableSigners[signer].key, req.Sensible)
		if signatureErr != nil {
			http.Error(w, "Unable to sign message", http.StatusInternalServerError)
			return
		}

		message.Signature = hex.EncodeToString(signedMessage)
		message.Signer = server.AvailableSigners[signer].key.Address.Hex()

		if !req.NoMetatx {
			// If no_metatx key not provided with request, prepare slices for push to metatx call requests creation endpoint
			newCallRequest := CallRequestSpecification{
				Caller:    message.Claimant,
				Method:    "claim",
				RequestId: message.RequestID,
				Parameters: DropperCallRequestParameters{
					DropId:        message.DropId,
					BlockDeadline: message.BlockDeadline,
					Amount:        message.Amount,
					Signer:        signer,
					Signature:     message.Signature,
				},
			}
			callRequestSpecifications = append(callRequestSpecifications, newCallRequest)
			currentBatch = append(currentBatch, newCallRequest)
			if (i+1)%batchSize == 0 || i == callRequestsLen-1 {
				if currentBatch != nil {
					callRequestBatches = append(callRequestBatches, currentBatch)
				}
				currentBatch = nil // Reset the batch
			}
		}
	}

	// Run check of existing call_requests in database
	if !req.NoMetatx && !req.NoCheckMetatx {
		checkStatusCode, existingRequests, checkStatus := server.MoonstreamEngineAPIClient.checkCallRequests(authorizationToken, req.RegisteredContractId, req.Dropper, callRequestSpecifications)

		if checkStatusCode == 0 {
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		} else if checkStatusCode == 200 {
			if len(existingRequests.ExistingRequests) != 0 {
				var existingReqIds string
				for i, r := range existingRequests.ExistingRequests {
					if i == 0 {
						existingReqIds += r[1]
						continue
					}
					existingReqIds += fmt.Sprintf(",%s", r[1])
				}
				http.Error(w, fmt.Sprintf("Conflicting records were found in the database: [%s]", existingReqIds), http.StatusConflict)
				return
			}
		} else {
			http.Error(w, checkStatus, checkStatusCode)
			return
		}
	}

	resp := SignDropperResponse{
		ChainId:  req.ChainId,
		Dropper:  req.Dropper,
		TtlDays:  req.TtlDays,
		Sensible: req.Sensible,
		Requests: req.Requests,
	}

	var jobEntry *spire.Entry
	// Prepare job entry for report
	if !req.NoMetatx {
		resp.MetatxRegistered = true

		var createJobErr error
		jobEntry, createJobErr = CreateJobInJournal(&server.BugoutAPIClient.BugoutSpireClient, signer)
		if createJobErr != nil {
			log.Printf("Unable to create job entry in journal, error: %v", createJobErr)
		}
	}

	if jobEntry != nil {
		resp.JobEntryId = jobEntry.Id
		resp.JobEntryUrl = fmt.Sprintf("%s/journals/%s/entries/%s", server.BugoutAPIClient.SpireBaseURL, BUGOUT_METATX_JOBS_JOURNAL_ID, jobEntry.Id)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)

	if !req.NoMetatx {
		pushedCallRequestIds := []string{}
		failedCallRequestIds := []string{}

		// Push batch by batch to metatx call requests creation endpoint in background
		go func() {
			for i, batchSpecs := range callRequestBatches {
				requestBody := CreateCallRequestsRequest{
					TTLDays:        req.TtlDays,
					Specifications: batchSpecs,
				}
				if req.RegisteredContractId != "" {
					requestBody.ContractID = req.RegisteredContractId
				} else {
					requestBody.ContractAddress = req.Dropper
				}

				requestBodyBytes, requestBodyBytesErr := json.Marshal(requestBody)
				if requestBodyBytesErr != nil {
					log.Printf("Unable to marshal body, error: %v", requestBodyBytesErr)
					for _, r := range batchSpecs {
						failedCallRequestIds = append(failedCallRequestIds, r.RequestId)
					}
					continue
				}

				statusCode, responseBodyStr := server.MoonstreamEngineAPIClient.sendCallRequests(authorizationToken, requestBodyBytes)
				if statusCode == 200 {
					for _, r := range batchSpecs {
						pushedCallRequestIds = append(pushedCallRequestIds, r.RequestId)
					}
					log.Printf("Batch %d of %d total with %d call_requests successfully pushed to API", i+1, len(callRequestBatches), callRequestsLen)
					continue
				}

				if statusCode == 409 {
					log.Printf("Batch %d of %d total with %d call_requests failed with duplication error: %v", i+1, len(callRequestBatches), callRequestsLen, responseBodyStr)
				} else {
					log.Printf("Batch %d of %d total with %d call_requests failed with error: %v", i+1, len(callRequestBatches), callRequestsLen, responseBodyStr)
				}
				for _, r := range batchSpecs {
					failedCallRequestIds = append(failedCallRequestIds, r.RequestId)
				}
			}

			// Send job report to entry
			if jobEntry != nil {
				jobStatusCode, writeJobErr := server.BugoutAPIClient.UpdateJobInJournal(jobEntry.Id, signer, pushedCallRequestIds, failedCallRequestIds)
				if writeJobErr != nil {
					log.Printf("Unable to push waggle job to journal, status code %d, error: %v", jobStatusCode, writeJobErr)
				}
			} else {
				log.Printf("Job entry creation failed, job report not pushed")
			}
		}()
	}
}

// Serve handles server run
func (server *Server) Serve() error {
	serveMux := http.NewServeMux()
	serveMux.Handle("/signers/", server.accessMiddleware(http.HandlerFunc(server.signersHandler)))
	serveMux.Handle("/holders", server.accessMiddleware(http.HandlerFunc(server.holdersHandler)))
	serveMux.HandleFunc("/ping", server.pingRoute)
	serveMux.HandleFunc("/version", server.versionRoute)

	// Set list of common middleware, from bottom to top
	commonHandler := server.corsMiddleware(serveMux)
	commonHandler = server.logMiddleware(commonHandler)
	commonHandler = server.panicMiddleware(commonHandler)

	s := http.Server{
		Addr:         fmt.Sprintf("%s:%d", server.Host, server.Port),
		Handler:      commonHandler,
		ReadTimeout:  180 * time.Second,
		WriteTimeout: 180 * time.Second,
	}

	log.Printf("Starting node load balancer HTTP server at %s:%d", server.Host, server.Port)
	sErr := s.ListenAndServe()
	if sErr != nil {
		return fmt.Errorf("failed to start server listener, err: %v", sErr)
	}

	return nil
}
