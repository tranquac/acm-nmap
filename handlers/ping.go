// handlers/ping.go
package handlers

import (
	"encoding/json"
	"net/http"
)

// Response định nghĩa cấu trúc JSON trả về
 type Response struct {
	Message string `json:"message"`
}

// PingHandler kiểm tra sức khỏe của server và trả về JSON
func PingHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(Response{Message: "pong"})
}