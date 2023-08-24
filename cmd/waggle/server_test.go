package waggle

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"testing"
)


func TestServerPingRoute(t *testing.T) {
	// Initialize Server instance and create Request to pass handler
	server := &Server{}
	r := httptest.NewRequest("GET", "/ping", nil)

	// Create ResponseRecoreder which statisfies http.ResponseWriter
	// to record the response.
	w := httptest.NewRecorder()

	server.PingRoute(w, r)

	result := w.Result()
	var resp PingResponse
	if err := json.NewDecoder(result.Body).Decode(&resp); err != nil {
		fmt.Printf("Error decoding response: %v", err)
	}
	defer result.Body.Close()
}
