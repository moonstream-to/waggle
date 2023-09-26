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
	"strings"
	"sync"
	"time"

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
	AvailableSigners          map[string]AvailableSigner
	LogLevel                  int
	CORSWhitelist             map[string]bool
	MoonstreamEngineAPIClient *MoonstreamEngineAPIClient

	ServerMu             sync.Mutex
	ServerWg             sync.WaitGroup
	ServerActiveRoutines map[string]*ServerRoutineInfo
}

type ServerRoutineInfo struct {
	Id        string `json:"id"`
	Operation string `json:"operation"`
	Status    string `json:"status"`
}

func (server *Server) RegisterServerRoutine(sri *ServerRoutineInfo) {
	server.ServerMu.Lock()
	server.ServerActiveRoutines[sri.Id] = sri
	server.ServerMu.Unlock()
	server.ServerWg.Add(1)
}

func (server *Server) ReleaseServerRoutine(sri *ServerRoutineInfo) {
	server.ServerMu.Lock()
	// TODO(kompotkot): Add background cleaner to remove memory leaks
	server.ServerActiveRoutines[sri.Id].Status = "Complete"
	server.ServerMu.Unlock()
	server.ServerWg.Done()
}

func (server *Server) InProgressServerRoutine(sri *ServerRoutineInfo) {
	server.ServerMu.Lock()
	server.ServerActiveRoutines[sri.Id].Status = "In Progress"
	server.ServerMu.Unlock()
}

func (server *Server) FailedServerRoutine(sri *ServerRoutineInfo) {
	server.ServerMu.Lock()
	server.ServerActiveRoutines[sri.Id].Status = "Failed"
	server.ServerMu.Unlock()
	server.ServerWg.Done()
}

func (server *Server) GetServerRoutine(id string) (*ServerRoutineInfo, bool) {
	server.ServerMu.Lock()
	routineInfo, routineExists := server.ServerActiveRoutines[id]
	server.ServerMu.Unlock()

	return routineInfo, routineExists
}

func (server *Server) CreateCallRequestsRoutine(sri *ServerRoutineInfo, authorizationToken string, req *SignDropperRequest, specs []CallRequestSpecification) {
	server.InProgressServerRoutine(sri)

	createReqErr := server.MoonstreamEngineAPIClient.CreateCallRequests(authorizationToken, "", req.Dropper, req.TtlDays, specs, 100, 1)
	if createReqErr != nil {
		server.FailedServerRoutine(sri)
		return
	}

	server.ReleaseServerRoutine(sri)
}

type PingResponse struct {
	Status string `json:"status"`
}

type SignDropperRequest struct {
	ChainId  int                    `json:"chain_id"`
	Dropper  string                 `json:"dropper"`
	Signer   string                 `json:"signer"`
	TtlDays  int                    `json:"ttl_days"`
	Sensible bool                   `json:"sensible"`
	Requests []*DropperClaimMessage `json:"requests"`

	ServerRoutineInfoId string `json:"server_routine_info_id"`
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
		if authorizationTokenRaw != "" {
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
		}

		ctxUser := context.WithValue(r.Context(), "authorizationToken", authorizationToken)

		next.ServeHTTP(w, r.WithContext(ctxUser))
	})
}

// CORS middleware
func (server *Server) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			var allowedOrigin string
			if server.CORSWhitelist["*"] {
				allowedOrigin = "*"
			} else {
				for o := range server.CORSWhitelist {
					if r.Header.Get("Origin") == o {
						allowedOrigin = o
					}
				}
			}
			// If origin in list of CORS allowed origins, extend with required headers
			if allowedOrigin != "" {
				w.Header().Set("Access-Control-Allow-Origin", allowedOrigin)
				w.Header().Set("Access-Control-Allow-Methods", "GET,POST")
				// Credentials are cookies, authorization headers, or TLS client certificates
				w.Header().Set("Access-Control-Allow-Credentials", "true")
				w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
			}
			w.WriteHeader(http.StatusNoContent)
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

// signDropperRoute sign dropper call requests
func (server *Server) signDropperRoute(w http.ResponseWriter, r *http.Request) {
	authorizationToken := r.Context().Value("authorizationToken").(string)

	isMetatxDrop := false
	queries := r.URL.Query()
	for k := range queries {
		if k == "is_metatx_drop" {
			isMetatxDrop = true
		}
	}

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

	// Check if server can sign with provided signer address
	var chosenSigner string
	for addr := range server.AvailableSigners {
		if addr == common.HexToAddress(req.Signer).String() {
			chosenSigner = addr
		}
	}
	if chosenSigner == "" {
		http.Error(w, "Unable to find signer", http.StatusBadRequest)
		return
	}

	callRequests := make([]CallRequestSpecification, len(req.Requests))
	for i, message := range req.Requests {
		messageHash, hashErr := DropperClaimMessageHash(int64(req.ChainId), req.Dropper, message.DropId, message.RequestID, message.Claimant, message.BlockDeadline, message.Amount)
		if hashErr != nil {
			http.Error(w, "Unable to generate message hash", http.StatusInternalServerError)
			return
		}

		signedMessage, signatureErr := SignRawMessage(messageHash, server.AvailableSigners[chosenSigner].key, req.Sensible)
		if signatureErr != nil {
			http.Error(w, "Unable to sign message", http.StatusInternalServerError)
			return
		}

		message.Signature = hex.EncodeToString(signedMessage)
		message.Signer = server.AvailableSigners[chosenSigner].key.Address.Hex()

		if isMetatxDrop {
			callRequests[i] = CallRequestSpecification{
				Caller:    message.Claimant,
				Method:    "claim",
				RequestId: message.RequestID,
				Parameters: DropperCallRequestParameters{
					DropId:        message.DropId,
					BlockDeadline: message.BlockDeadline,
					Amount:        message.Amount,
					Signer:        message.Signer,
					Signature:     message.Signature,
				},
			}
		}
	}

	if isMetatxDrop {
		newSri := ServerRoutineInfo{
			Id:        uuid.New().String(),
			Operation: "Create call_requests at metatx Engine API",
			Status:    "Initialized",
		}
		server.RegisterServerRoutine(&newSri)
		go server.CreateCallRequestsRoutine(&newSri, authorizationToken, req, callRequests)
		req.ServerRoutineInfoId = newSri.Id
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(req)
}

// InfoRoutinesRoute response with status of call requests registration at metatx Engine API
func (server *Server) InfoRoutinesRoute(w http.ResponseWriter, r *http.Request) {
	urlParts := strings.Split(r.URL.Path, "/")
	if len(urlParts) > 3 {
		sriId := urlParts[3]
		_, uuidParseErr := uuid.Parse(sriId)
		if uuidParseErr != nil {
			http.Error(w, "Incorrect routine info ID provided", http.StatusBadRequest)
			return
		}

		routineInfo, routineExists := server.GetServerRoutine(sriId)
		if !routineExists {
			http.Error(w, "Routine info not found", http.StatusNotFound)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(routineInfo)
	} else {
		http.Error(w, "Invalid URL", http.StatusBadRequest)
		return
	}
}

// Serve handles server run
func (server *Server) Serve() error {
	serveMux := http.NewServeMux()
	serveMux.HandleFunc("/ping", server.pingRoute)
	serveMux.HandleFunc("/sign/dropper", server.signDropperRoute)
	serveMux.HandleFunc("/info/routines/", server.InfoRoutinesRoute)

	// Set list of common middleware, from bottom to top
	commonHandler := server.accessMiddleware(serveMux)
	commonHandler = server.corsMiddleware(commonHandler)
	commonHandler = server.logMiddleware(commonHandler)
	commonHandler = server.panicMiddleware(commonHandler)

	s := http.Server{
		Addr:         fmt.Sprintf("%s:%d", server.Host, server.Port),
		Handler:      commonHandler,
		ReadTimeout:  40 * time.Second,
		WriteTimeout: 40 * time.Second,
	}

	log.Printf("Starting node load balancer HTTP server at %s:%d", server.Host, server.Port)
	sErr := s.ListenAndServe()
	if sErr != nil {
		return fmt.Errorf("failed to start server listener, err: %v", sErr)
	}

	return nil
}
