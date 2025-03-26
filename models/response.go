package models

// ScanResult chứa kết quả scan của một IP
type ScanResult struct {
	IP     string     `json:"ip"`
	Status string     `json:"status"`
	Ports  []PortInfo `json:"ports"`
}

// PortInfo chứa thông tin về port mở
type PortInfo struct {
	Port    string `json:"port"`    // Ví dụ: "80/tcp"
	Service string `json:"service"` // Ví dụ: "http"
	Version string `json:"version"` // Ví dụ: "Apache httpd 2.4.41"
}
