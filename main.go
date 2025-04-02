package main

import (
    "fmt"
    "log"
    "net/http"
    "github.com/joho/godotenv"
    "acm-nmap/handlers"
    "acm-nmap/middlewares"
)

func main() {
    // Load .env file
    err := godotenv.Load()
    if err != nil {
        log.Fatal("Error loading .env file")
    }

    http.Handle("/ping", middlewares.CheckAPIKey(http.HandlerFunc(handlers.PingHandler)))
    http.Handle("/acm/v1/nmap", middlewares.CheckAPIKey(http.HandlerFunc(handlers.NmapHandler)))
    http.Handle("/acm/v1/log", middlewares.CheckAPIKey(http.HandlerFunc(handlers.GetScanLog)))

    fmt.Println("Server is running on port 9899...")
    log.Fatal(http.ListenAndServe(":9899", nil))
}
