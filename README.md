# acm-nmap

acm-nmap is a Golang-based API service that leverages the nmap tool to scan IP addresses and retrieve open ports, running services, and their versions. The service supports parallel scanning of up to 10 IPs at a time, stores scan results temporarily for one hour, and provides API endpoints to check scan statuses and logs.

## Features

- Health check API (/ping): Returns pong as JSON.

- Nmap scan API (/acm/v1/nmap): Accepts up to 10 IPs, executes nmap to retrieve open ports and service versions, and returns real-time status.

- Scan log API (/acm/v1/log): Displays the current IPs being scanned and their statuses.

- Automatic scan reset: Results are cleared every hour to ensure fresh scans.

## API Endpoints

### 1. Health Check

Endpoint: GET /ping

Response:
```
{
  "message": "pong"
}
```
### 2. Nmap Scan

Endpoint: GET /acm/v1/nmap

Response:
```
{
  "ip": "127.0.0.1",
  "status": "completed",
  "ports": [
    { "port": "22/tcp", "service": "ssh", "version": "OpenSSH 7.9p1" },
    { "port": "80/tcp", "service": "http", "version": "Apache 2.4.41" }
  ]
}
```
### 3. Scan Log

Endpoint: GET /acm/v1/log

Response (example):
```
{
  "127.0.0.1": "scanning",
  "192.168.1.10": "completed",
  "8.8.8.8": "timeout"
}
```
## Installation & Running

### Prerequisites

- Golang installed (```>=1.18```)

- ```nmap``` installed (```sudo apt install nmap``` for Linux, ```brew install nmap``` for macOS)

### Steps to Run

Clone the repository:
```
git clone https://github.com/your-repo/acm-nmap.git
cd acm-nmap
```
Install dependencies:
```
go mod tidy
```
Run the service (Default run in port 9899):
```
go run main.go
```

### Or directly download from Releases