package handlers

import (
	"acm-nmap/services"
	"encoding/json"
	"net/http"
)

func GetScanLog(w http.ResponseWriter, r *http.Request) {
	logData := services.GetCurrentScans()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(logData)
}
