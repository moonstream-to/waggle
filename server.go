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
	ChainId  int                    `json:"chain_id"`
	Dropper  string                 `json:"dropper"`
	TtlDays  int                    `json:"ttl_days"`
	Sensible bool                   `json:"sensible"`
	Requests []*DropperClaimMessage `json:"requests"`

	NoMetatx bool `json:"no_metatx"`
}

type SignDropperResponse struct {
	ChainId  int                    `json:"chain_id"`
	Dropper  string                 `json:"dropper"`
	TtlDays  int                    `json:"ttl_days"`
	Sensible bool                   `json:"sensible"`
	Requests []*DropperClaimMessage `json:"requests"`

	MetatxRegistered bool `json:"metatx_registered"`
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
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(accessResourceHolders.Holders)
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
	switch r.Method {
	case http.MethodGet:
		server.signersRoute(w, r)
		return
	case http.MethodPost:
		routePathSlice := strings.Split(r.URL.Path, "/")
		requestedSigner := common.HexToAddress(routePathSlice[2]).String()
		_, ok := server.AvailableSigners[requestedSigner]
		if !ok {
			http.Error(w, fmt.Sprintf("Unacceptable signer provided %s", requestedSigner), http.StatusBadRequest)
			return
		}
		switch {
		case strings.Contains(r.URL.Path, "/dropper/sign"):
			// TODO: (kompotkot): Re-write in subroutes and subapps when times come
			server.signDropperRoute(w, r, requestedSigner)
			return
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

// signDropperRoute sign dropper call requests
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

	callRequests := make([]CallRequestSpecification, len(req.Requests))
	for i, message := range req.Requests {
		messageHash, hashErr := DropperClaimMessageHash(int64(req.ChainId), req.Dropper, message.DropId, message.RequestID, message.Claimant, message.BlockDeadline, message.Amount)
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
			callRequests[i] = CallRequestSpecification{
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
		}
	}

	resp := SignDropperResponse{
		ChainId:  req.ChainId,
		Dropper:  req.Dropper,
		TtlDays:  req.TtlDays,
		Sensible: req.Sensible,
		Requests: req.Requests,
	}

	if !req.NoMetatx {
		createReqErr := server.MoonstreamEngineAPIClient.CreateCallRequests(authorizationToken, "", req.Dropper, req.TtlDays, callRequests, 100, 1)
		if createReqErr == nil {
			log.Printf("New %d call_requests registered at metatx for %s", len(callRequests), req.Dropper)
			resp.MetatxRegistered = true
		}
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
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
