package main

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

type host struct {
	IP        string `json:"ip"`
	Hostname  string `json:"hostname"`
	Active    bool   `json:"active"`
	IsLocal   bool   `json:"is_local"`   
	IsGateway bool   `json:"is_gateway"` 
}

func getLocalIP() string {
	conn, err := net.Dial("udp", "10.254.254.254:1")
	if err != nil {
		return "127.0.0.1"
	}
	defer conn.Close()
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP.String()
}

func getGateway() string {
	var cmd *exec.Cmd

	if runtime.GOOS == "windows" {
		
		cmd = exec.Command("cmd", "/c", "ipconfig | findstr /i \"Default Gateway\" | head -1")
	} else {
		
		cmd = exec.Command("sh", "-c", "ip route | grep default | head -1 | awk '{print $3}'")
	}

	output, err := cmd.Output()
	if err != nil {
		
		if runtime.GOOS == "windows" {
			return getGatewayWindowsFallback()
		}
		return ""
	}

	result := strings.TrimSpace(string(output))

	if runtime.GOOS == "windows" {
		
		parts := strings.Split(result, ":")
		if len(parts) > 1 {
			return strings.TrimSpace(parts[1])
		}
		return ""
	}

	return result
}

func getGatewayWindowsFallback() string {
	
	cmd := exec.Command("cmd", "/c", "netsh interface ip show config | findstr /i \"Gateway\"")
	output, err := cmd.Output()
	if err != nil {
		return ""
	}

	result := strings.TrimSpace(string(output))
	lines := strings.Split(result, "\n")
	for _, line := range lines {
		if strings.Contains(line, "Default Gateway") {
			parts := strings.Split(line, ":")
			if len(parts) > 1 {
				return strings.TrimSpace(parts[1])
			}
		}
	}

	return ""
}

func getCurrentDir() string {
	dir, err := os.Getwd()
	if err != nil {
		return "."
	}
	return dir
}

func getParentDir() string {
	currentDir := getCurrentDir()
	return filepath.Dir(currentDir)
}

func generateIPs(localIP string) []string {
	parts := strings.Split(localIP, ".")
	base := fmt.Sprintf("%s.%s.%s.", parts[0], parts[1], parts[2])
	ips := make([]string, 0, 254)
	for i := 1; i <= 254; i++ {
		ips = append(ips, fmt.Sprintf("%s%d", base, i))
	}
	return ips
}

func pingHost(ip string, timeout time.Duration, retries int) bool {
	for i := 0; i < retries; i++ {
		if pingOnce(ip, timeout) {
			return true
		}
		time.Sleep(100 * time.Millisecond)
	}
	return false
}

func pingOnce(ip string, timeout time.Duration) bool {
	
	network := "ip4:icmp"
	if runtime.GOOS == "windows" {
		network = "ip:icmp"
	}

	conn, err := icmp.ListenPacket(network, "0.0.0.0")
	if err != nil {
		return false
	}
	defer conn.Close()

	id := os.Getpid() & 0xffff
	seq := uint16(rand.Intn(0xffff))

	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   id,
			Seq:  int(seq),
			Data: []byte("HELLO"),
		},
	}
	b, _ := msg.Marshal(nil)
	dst := &net.IPAddr{IP: net.ParseIP(ip)}

	start := time.Now()
	if _, err := conn.WriteTo(b, dst); err != nil {
		return false
	}

	conn.SetReadDeadline(time.Now().Add(timeout))
	reply := make([]byte, 1500)
	n, peer, err := conn.ReadFrom(reply)
	if err != nil {
		return false
	}

	if !strings.HasPrefix(peer.String(), ip) {
		return false
	}

	resp, err := icmp.ParseMessage(1, reply[:n])
	if err != nil {
		return false
	}
	echo, ok := resp.Body.(*icmp.Echo)
	if !ok || echo.ID != id || echo.Seq != int(seq) {
		return false
	}

	return time.Since(start) < timeout
}

func resolveHostname(ip string) (string, bool) {
	names, err := net.LookupAddr(ip)
	if err != nil || len(names) == 0 {
		return ip, false
	}
	return strings.TrimSuffix(names[0], "."), true
}

func sortHosts(hosts []host) {
	sort.Slice(hosts, func(i, j int) bool {
		aParts := strings.Split(hosts[i].IP, ".")
		bParts := strings.Split(hosts[j].IP, ".")
		for k := 0; k < 4; k++ {
			a, _ := strconv.Atoi(aParts[k])
			b, _ := strconv.Atoi(bParts[k])
			if a != b {
				return a < b
			}
		}
		return false
	})
}

func main() {
	rand.Seed(time.Now().UnixNano())

	localIP := getLocalIP()
	gatewayIP := getGateway()
	
	parentDir := getParentDir()

	fmt.Println("IP Local Detectado:", localIP)
	fmt.Println("Gateway Detectado:", gatewayIP)
	
	fmt.Printf("\nSub-rede: %s/24\n", strings.Join(strings.Split(localIP, ".")[:3], "."))
	fmt.Println("\nEscaneando Sub-rede.\n")

	ips := generateIPs(localIP)
	var wg sync.WaitGroup
	sem := make(chan struct{}, 50) 

	var mu sync.Mutex
	discovered := make([]host, 0)

	for _, ip := range ips {
		wg.Add(1)
		sem <- struct{}{}
		go func(ip string) {
			defer wg.Done()

			active := pingHost(ip, 2*time.Second, 10)
			hostname := ip

			hostnameTmp, ok := resolveHostname(ip)
			if ok {
				hostname = hostnameTmp
			}

			if active || ok {
				mu.Lock()
				
				isLocal := ip == localIP
				isGateway := ip == gatewayIP

				discovered = append(discovered, host{
					IP:        ip,
					Hostname:  hostname,
					Active:    active,
					IsLocal:   isLocal,
					IsGateway: isGateway,
				})
				fmt.Printf("\rHosts descobertos: %d", len(discovered))
				mu.Unlock()
			}

			<-sem
		}(ip)
	}

	wg.Wait()

	sortHosts(discovered)

	var ativos []host
	var inativos []host
	for _, h := range discovered {
		if h.Active {
			ativos = append(ativos, h)
		} else {
			inativos = append(inativos, h)
		}
	}

	if len(inativos) > 0 {
		fmt.Println("\n\n---Inativos---")
		for _, h := range inativos {
			info := h.IP
			if h.Hostname != h.IP {
				info = fmt.Sprintf("%s (%s)", h.IP, h.Hostname)
			}
			if h.IsLocal {
				info += " " 
			}
			if h.IsGateway {
				info += " " 
			}
			fmt.Println("Host:", info)
		}
	}

	if len(ativos) > 0 {
		fmt.Println("\n---Ativos---")
		for _, h := range ativos {
			info := h.IP
			if h.Hostname != h.IP {
				info = fmt.Sprintf("%s (%s)", h.IP, h.Hostname)
			}
			if h.IsLocal {
				info += " [LOCAL]"
			}
			if h.IsGateway {
				info += " [GATEWAY]"
			}
			fmt.Println("Host:", info)
		}
	}

	fmt.Println("\nScan concluído.")

	jsonDir := filepath.Join(parentDir, "json")
	if err := os.MkdirAll(jsonDir, 0755); err != nil {
		fmt.Println("Erro ao criar diretório json:", err)
		return
	}

	jsonPath := filepath.Join(jsonDir, "hosts.json")
	file, err := os.Create(jsonPath)
	if err != nil {
		fmt.Println("Erro ao criar arquivo JSON:", err)
		return
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ") 
	if err := encoder.Encode(discovered); err != nil {
		fmt.Println("Erro ao salvar JSON:", err)
		return
	}

	fmt.Printf("Resultado salvo em %s\n", jsonPath)
}