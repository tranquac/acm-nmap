package services

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"io"
	"time"
	"acm-nmap/models"
)

var (
	openPortRegex = regexp.MustCompile(`(?m)^(\d+)/(tcp|udp)\s+open\s+(\S+)\s*(.*)?$`)
	discoveredPortRegex = regexp.MustCompile(`Discovered open port (\d+)/(tcp|udp)`)
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

func RunNmap(ipOrDomain string, timeout int) *models.ScanResult {
	mu.Lock()
	defer mu.Unlock()

	resolvedIP := ipOrDomain
	ips, err := net.LookupIP(ipOrDomain)
	if err == nil {
		for _, ip := range ips {
			if ip.To4() != nil { // Chỉ lấy IPv4
				resolvedIP = ip.String()
				break
			}
		}
	}

	// Format domain/IP nếu input là domain
	displayIP := resolvedIP
	if ipOrDomain != resolvedIP {
		displayIP = fmt.Sprintf("%s/%s", ipOrDomain, resolvedIP)
	}

	// Nếu đã scan trước đó thì trả về luôn
	if result, exists := scanResults[resolvedIP]; exists {
		result.IP = displayIP // Cập nhật IP hiển thị
		return result
	}

	// Tạo kết quả mới với trạng thái "scanning"
	scanResults[resolvedIP] = &models.ScanResult{
		IP:      displayIP, // Lưu dạng domain/IP
		Status:  "scanning",
		Ports:   []models.PortInfo{},
		Timeout: timeout,
	}

	// Hàng đợi chỉ cho phép tối đa 10 scan chạy cùng lúc
	sem <- struct{}{}
	go func() {
		defer func() { <-sem }() // Giải phóng slot khi scan xong
		result := executeNmap(resolvedIP, timeout)
		result.IP = displayIP // Đảm bảo kết quả trả về có domain/IP

		mu.Lock()
		scanResults[resolvedIP] = result
		mu.Unlock()
	}()

	return scanResults[resolvedIP]
}


func executeNmap(ipOrDomain string, timeout int) *models.ScanResult {
	result := &models.ScanResult{
		IP:     ipOrDomain,
		Status: "scanning",
		Ports:  []models.PortInfo{},
	}

	cmd := exec.Command("nmap", "-p-", "-sS", "-sU", "-sV", "-v", ipOrDomain)

	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()
	if err := cmd.Start(); err != nil {
		result.Status = "error"
		return result
	}

	var rawOutput strings.Builder
	done := make(chan struct{})

	// Đọc stdout và stderr
	go func() {
		scanner := bufio.NewScanner(io.MultiReader(stdout, stderr))
		for scanner.Scan() {
			line := scanner.Text()
			rawOutput.WriteString(line + "\n")
		}
		close(done)
	}()

	select {
	case <-done:
		result.Status = "completed"
	case <-time.After(time.Duration(timeout) * time.Second):
		result.Status = "timeout"
		cmd.Process.Kill()
		<-done // Đảm bảo đọc hết buffer
	}

	// Parse những gì đã có, kể cả khi timeout
	result.Ports = extractOpenPorts(rawOutput.String())

	// Trả về domain/ip nếu là domain
	if net.ParseIP(ipOrDomain) == nil {
		ips, _ := net.LookupIP(ipOrDomain)
		if len(ips) > 0 {
			result.IP = fmt.Sprintf("%s/%s", ipOrDomain, ips[0].String())
		}
	}

	return result
}



// extractOpenPorts lọc kết quả Nmap thành danh sách JSON
func extractOpenPorts(nmapOutput string) []models.PortInfo {
	scanner := bufio.NewScanner(strings.NewReader(nmapOutput))
	var ports []models.PortInfo
	seen := make(map[string]bool)

	for scanner.Scan() {
		line := scanner.Text()

		// Kiểu đầy đủ: "80/tcp open http Apache/2.4.41"
		if matches := openPortRegex.FindStringSubmatch(line); len(matches) >= 4 {
			key := fmt.Sprintf("%s/%s", matches[1], matches[2])
			if !seen[key] {
				ports = append(ports, models.PortInfo{
					Port:    key,
					Service: matches[3],
					Version: strings.TrimSpace(matches[4]),
				})
				seen[key] = true
			}
			continue
		}

		// Kiểu rút gọn: "Discovered open port 80/tcp on x.x.x.x"
		if matches := discoveredPortRegex.FindStringSubmatch(line); len(matches) == 3 {
			key := fmt.Sprintf("%s/%s", matches[1], matches[2])
			if !seen[key] {
				ports = append(ports, models.PortInfo{
					Port:    key,
					Service: "(unknown)",
					Version: "",
				})
				seen[key] = true
			}
		}
	}

	return ports
}

func GetCurrentScans() map[string]map[string]interface{} {
	mu.Lock()
	defer mu.Unlock()

	scanLog := make(map[string]map[string]interface{})
	for _, result := range scanResults {
		scanLog[result.IP] = map[string]interface{}{
			"status":  result.Status,
			"timeout": result.Timeout,
		}
	}
	return scanLog
}




