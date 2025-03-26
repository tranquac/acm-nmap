package main

import (
    "fmt"
    "log"
    "net/http"
    "acm-nmap/handlers"
)

func main() {
    http.HandleFunc("/ping", handlers.PingHandler)
    http.HandleFunc("/acm/v1/nmap", handlers.NmapHandler)
    http.HandleFunc("/acm/v1/log", handlers.GetScanLog)

    fmt.Println("Server is running on port 9899...")
    log.Fatal(http.ListenAndServe(":9899", nil))
}