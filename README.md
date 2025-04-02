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
Example:
```
curl -H "X-API-Key: mysecretkey" http://localhost:9899/acm/v1/ping
```
### 2. Nmap Scan

Endpoint: GET /acm/v1/nmap?ip=127.0.0.1&timeout=200s

Default timeout is 300s

Example:
```
curl -H "X-API-Key: mysecretkey" http://localhost:9899/acm/v1/nmap?ip=voz.vn
```

Response:
```
{
  "ip": "127.0.0.1",
  "status": "completed",
  "ports": [
    { "port": "22/tcp", "service": "ssh", "version": "OpenSSH 7.9p1" },
    { "port": "80/tcp", "service": "http", "version": "Apache 2.4.41" }
  ],
  "timeout":150
}
```
### 3. Scan Log

Endpoint: GET /acm/v1/log

Example:
```
curl -H "X-API-Key: mysecretkey" http://localhost:9899/acm/v1/log
```
Response (example):
```
{
  "127.0.0.1":{"status":"completed","timeout":300},
  "127.0.0.2":{"status":"completed","timeout":150},
  "127.0.0.3":{"status":"completed","timeout":300}
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

### Create acm-nmap as a service in linux

Move the binary to /usr/local/bin/ to run it from anywhere:
```
sudo mv acm-nmap-linux /usr/local/bin/acm-nmap
sudo chmod +x /usr/local/bin/acm-nmap
```
Create a new service file:
```
sudo nano /etc/systemd/system/acm-nmap.service
```
Paste the following content:
```
[Unit]
Description=ACM Nmap Service
After=network.target

[Service]
ExecStart=/usr/local/bin/acm-nmap
Restart=always
User=root
WorkingDirectory=/usr/local/bin
StandardOutput=append:/var/log/acm-nmap.log
StandardError=append:/var/log/acm-nmap.log
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target

```
Reload Systemd to detect the new service:
```
sudo systemctl daemon-reload
```
Start the service in the background:
```
sudo systemctl start acm-nmap
```
Check service status:
```
sudo systemctl status acm-nmap
```
Enable the service to start on boot:
```
sudo systemctl enable acm-nmap
```
Stop the service:
```
sudo systemctl stop acm-nmap
```
Restart the service:
```
sudo systemctl restart acm-nmap
```