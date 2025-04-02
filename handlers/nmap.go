package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"
	"acm-nmap/services"
)

func NmapHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	// Lấy IP từ query parameter (có thể là domain)
	ipOrDomain := r.URL.Query().Get("ip")
	if ipOrDomain == "" {
		http.Error(w, `{"error": "missing IP parameter"}`, http.StatusBadRequest)
		return
	}

	// Lấy timeout từ query parameter (nếu có)
	timeoutParam := r.URL.Query().Get("timeout")
	timeout := 200 // default timeout (giây)
	if timeoutParam != "" {
		var err error
		timeout, err = strconv.Atoi(timeoutParam)
		if err != nil {
			http.Error(w, `{"error": "invalid timeout value"}`, http.StatusBadRequest)
			return
		}
	}

	// Gọi RunNmap với IP và timeout
	result := services.RunNmap(ipOrDomain, timeout)

	// Trả về kết quả scan dưới dạng JSON
	json.NewEncoder(w).Encode(result)
}


