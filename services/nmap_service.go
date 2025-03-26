package services

import (
	"bufio"
	"fmt"
	"log"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"time"
	"acm-nmap/models"
)

var (
	// Regex mới để bắt port, protocol, service và version
	openPortRegex = regexp.MustCompile(`(?m)^(\d+)/(tcp|udp)\s+open\s+(\S+)\s*(.*)?$`)
	scanResults   = make(map[string]*models.ScanResult)
	mu            sync.Mutex
	sem           = make(chan struct{}, 10) // Giới hạn tối đa 10 scan song song
)

// Khởi động goroutine xóa dữ liệu sau 1 giờ
func init() {
	go func() {
		for {
			time.Sleep(1 * time.Hour)
			mu.Lock()
			scanResults = make(map[string]*models.ScanResult)
			log.Println("[INFO] Remove old scan")
			mu.Unlock()
		}
	}()
}

// RunNmap kiểm tra trạng thái hoặc bắt đầu scan nếu cần
func RunNmap(ip string) *models.ScanResult {
	mu.Lock()
	defer mu.Unlock()

	if result, exists := scanResults[ip]; exists {
		return result // Trả về nếu IP này đã có kết quả
	}

	// Tạo kết quả mới với trạng thái "scanning"
	scanResults[ip] = &models.ScanResult{
		IP:     ip,
		Status: "scanning",
		Ports:  []models.PortInfo{},
	}

	// Hàng đợi chỉ cho phép tối đa 10 scan chạy cùng lúc
	sem <- struct{}{}
	go func() {
		defer func() { <-sem }() // Giải phóng slot khi scan xong
		result := executeNmap(ip)

		mu.Lock()
		scanResults[ip] = result
		mu.Unlock()
	}()

	return scanResults[ip]
}

// executeNmap thực thi lệnh Nmap
func executeNmap(ip string) *models.ScanResult {
	result := &models.ScanResult{
		IP:     ip,
		Status: "scanning",
		Ports:  []models.PortInfo{},
	}

	cmd := exec.Command("nmap", "-p-", "-sS", "-sU", "-sV", ip)

	outputChan := make(chan string, 1)
	go func() {
		out, err := cmd.CombinedOutput()
		if err != nil {
			outputChan <- fmt.Sprintf("error: %v", err)
		} else {
			outputChan <- string(out)
		}
	}()

	select {
	case output := <-outputChan:
		if strings.Contains(output, "Failed to resolve") {
			result.Status = "can not connect to IP"
		} else {
			result.Status = "completed"
			result.Ports = extractOpenPorts(output)
		}
	case <-time.After(300 * time.Second):
		cmd.Process.Kill()
		result.Status = "timeout"
	}

	return result
}

// extractOpenPorts lọc kết quả Nmap thành danh sách JSON
func extractOpenPorts(nmapOutput string) []models.PortInfo {
	scanner := bufio.NewScanner(strings.NewReader(nmapOutput))
	var ports []models.PortInfo

	for scanner.Scan() {
		line := scanner.Text()
		matches := openPortRegex.FindStringSubmatch(line)
		if len(matches) >= 4 {
			portInfo := models.PortInfo{
				Port:    fmt.Sprintf("%s/%s", matches[1], matches[2]),
				Service: matches[3],
				Version: strings.TrimSpace(matches[4]), // Lấy version của service (nếu có)
			}
			ports = append(ports, portInfo)
		}
	}

	return ports
}


// GetCurrentScans trả về danh sách IP và trạng thái hiện tại
func GetCurrentScans() map[string]string {
	mu.Lock()
	defer mu.Unlock()

	scanLog := make(map[string]string)
	for ip, result := range scanResults {
		scanLog[ip] = result.Status
	}
	return scanLog
}
