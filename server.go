package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/common"
)

type AvailableSigner struct {
	key *keystore.Key
}

type Server struct {
	Host             string
	Port             int
	AvailableSigners map[string]AvailableSigner
	LogLevel         int
	CORSWhitelist    map[string]bool
}

type PingResponse struct {
	Status string `json:"status"`
}

type SignDropperRequest struct {
	ChainId  int                    `json:"chain_id"`
	Dropper  string                 `json:"dropper"`
	Signer   string                 `json:"signer"`
	Sensible bool                   `json:"sensible"`
	Requests []*DropperClaimMessage `json:"requests"`
}

// CORS middleware
// TODO: Use server.CORSWhitelist (check wildcard first).
func (server *Server) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			for _, allowedOrigin := range strings.Split(WAGGLE_CORS_ALLOWED_ORIGINS, ",") {
				if r.Header.Get("Origin") == allowedOrigin {
					w.Header().Set("Access-Control-Allow-Origin", allowedOrigin)
					w.Header().Set("Access-Control-Allow-Methods", "GET,POST")
					// Credentials are cookies, authorization headers, or TLS client certificates
					w.Header().Set("Access-Control-Allow-Credentials", "true")
					w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
				}
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// Log access requests in proper format
// TODO: User server.LogLevel.
func (server *Server) logMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := ioutil.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "Unable to read body", http.StatusBadRequest)
			return
		}
		r.Body = ioutil.NopCloser(bytes.NewBuffer(body))
		if len(body) > 0 {
			defer r.Body.Close()
		}

		next.ServeHTTP(w, r)

		var ip string
		realIp := r.Header["X-Real-Ip"]
		if len(realIp) == 0 {
			ip, _, err = net.SplitHostPort(r.RemoteAddr)
			if err != nil {
				http.Error(w, fmt.Sprintf("Unable to parse client IP: %s", r.RemoteAddr), http.StatusBadRequest)
				return
			}
		} else {
			ip = realIp[0]
		}
		logStr := fmt.Sprintf("%s %s %s", ip, r.Method, r.URL.Path)
		log.Printf("%s\n", logStr)
	})
}

// Handle panic errors to prevent server shutdown
func (server *Server) panicMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				log.Println("recovered", err)
				http.Error(w, "Internal server error", 500)
			}
		}()

		// There will be a defer with panic handler in each next function
		next.ServeHTTP(w, r)
	})
}

// pingRoute response with status of load balancer server itself
func (server *Server) pingRoute(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	response := PingResponse{Status: "ok"}
	json.NewEncoder(w).Encode(response)
}

// signDropperRoute response with status of load balancer server itself
// TODO: Use server.AvailableSigners
func (server *Server) signDropperRoute(w http.ResponseWriter, r *http.Request) {
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Unable to read body", http.StatusBadRequest)
		return
	}
	r.Body = ioutil.NopCloser(bytes.NewBuffer(body))
	if len(body) > 0 {
		defer r.Body.Close()
	}
	var req *SignDropperRequest
	err = json.Unmarshal(body, &req)
	if err != nil {
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

	for _, message := range req.Requests {
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
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(req)
}

// TODO: Remove host and port arguments- these should be read from server.Host, server.Port.
func (server *Server) Serve(host string, port int) error {
	serveMux := http.NewServeMux()
	serveMux.HandleFunc("/ping", server.pingRoute)
	serveMux.HandleFunc("/sign/dropper", server.signDropperRoute)

	// Set list of common middleware, from bottom to top
	commonHandler := server.corsMiddleware(serveMux)
	commonHandler = server.logMiddleware(commonHandler)
	commonHandler = server.panicMiddleware(commonHandler)

	s := http.Server{
		Addr:         fmt.Sprintf("%s:%d", host, port),
		Handler:      commonHandler,
		ReadTimeout:  40 * time.Second,
		WriteTimeout: 40 * time.Second,
	}

	log.Printf("Starting node load balancer HTTP server at %s:%d", host, port)
	err := s.ListenAndServe()
	if err != nil {
		return fmt.Errorf("failed to start server listener, err: %v", err)
	}

	return nil
}
