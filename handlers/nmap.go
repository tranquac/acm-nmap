package handlers

import (
	"encoding/json"
	"net/http"
	"acm-nmap/services"
)

func NmapHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// Lấy IP từ query parameter
	ip := r.URL.Query().Get("ip")
	if ip == "" {
		http.Error(w, `{"error": "missing IP parameter"}`, http.StatusBadRequest)
		return
	}

	// Chỉ truyền 1 tham số (IP) vào hàm RunNmap
	result := services.RunNmap(ip)

	// Trả về JSON response
	json.NewEncoder(w).Encode(result)
}
