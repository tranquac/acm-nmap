package middlewares

import (
	"net/http"
	"os"
)

// CheckAPIKey xác thực API-Key từ header request
func CheckAPIKey(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Đọc API-Key từ biến môi trường (đã load từ .env)
		validAPIKey := os.Getenv("API_KEY")
		if validAPIKey == "" {
			http.Error(w, `{"error": "server API key not set"}`, http.StatusInternalServerError)
			return
		}

		// Lấy API-Key từ header request
		apiKey := r.Header.Get("X-API-Key")
		if apiKey == "" || apiKey != validAPIKey {
			http.Error(w, `{"error": "unauthorized"}`, http.StatusUnauthorized)
			return
		}

		// Nếu API-Key đúng, cho phép request tiếp tục
		next.ServeHTTP(w, r)
	})
}
