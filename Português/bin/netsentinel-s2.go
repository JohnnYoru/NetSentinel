package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

type Port struct {
	Number int    `json:"number"`
	State  string `json:"state"`
	Proto  string `json:"proto"`
}

type Host struct {
	IP        string `json:"ip"`
	Hostname  string `json:"hostname"`
	Active    bool   `json:"active"`
	IsLocal   bool   `json:"is_local"`
	IsGateway bool   `json:"is_gateway"`
	Firewall  bool   `json:"firewall,omitempty"`
	Ports     []Port `json:"ports,omitempty"`
	Evasion   string `json:"evasion,omitempty"`
}

type EvadeScan struct {
	Args []string
}

var evadeScans = []EvadeScan{
	{Args: []string{"-sS", "-f", "-Pn"}},
	{Args: []string{"-sS", "-Pn", "-g", "88"}},
	{Args: []string{"-sS", "--min-rate", "5000", "-T4"}},
	{Args: []string{"-sS", "-Pn", "-f", "--mtu", "16", "-D", "RND:10", "--data-length", "32", "--scan-delay", "500ms", "-p", "80,443,8080"}},
	{Args: []string{"-sU", "-p", "53,67,88,123,137,138,139,143,161,162", "--data-length", "64"}},
}

const hostTimeout = 3 * time.Minute

type StatusBoard struct {
	mu         sync.Mutex
	inProgress map[string]string
	finished   map[string]string
	timedOut   map[string]string
}

func NewStatusBoard() *StatusBoard {
	return &StatusBoard{
		inProgress: make(map[string]string),
		finished:   make(map[string]string),
		timedOut:   make(map[string]string),
	}
}

func (s *StatusBoard) Start(host *Host) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.inProgress[host.IP] = host.Hostname
	s.render()
}

func (s *StatusBoard) Finish(host *Host) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.inProgress, host.IP)
	s.finished[host.IP] = host.Hostname
	s.render()
}

func (s *StatusBoard) Timeout(host *Host) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.inProgress, host.IP)
	s.timedOut[host.IP] = host.Hostname
	s.render()
}

func (s *StatusBoard) render() {
	fmt.Print("\033[H\033[2J")
	fmt.Println("Hosts em progresso:")
	for ip, h := range s.inProgress {
		fmt.Printf(" - %s (%s)\n", h, ip)
	}
	fmt.Println("\nHosts finalizados:")
	for ip, h := range s.finished {
		fmt.Printf(" - %s (%s)\n", h, ip)
	}
	if len(s.timedOut) > 0 {
		fmt.Println("\nHosts ignorados (timeout):")
		for ip, h := range s.timedOut {
			fmt.Printf(" - %s (%s)\n", h, ip)
		}
	}
}

func getCurrentDir() string {
	dir, err := os.Getwd()
	if err != nil {
		return "."
	}
	return dir
}

func getParentDir() string {
	return filepath.Dir(getCurrentDir())
}

func runNmap(ctx context.Context, ip string, args ...string) (string, error) {
	cmdArgs := append(args, ip)
	cmd := exec.CommandContext(ctx, "nmap", cmdArgs...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	return out.String(), err
}

func parseNmapOutput(output string) (firewall bool, ports []Port) {
	lines := strings.Split(output, "\n")
	ports = []Port{}
	openCount := 0
	filteredCount := 0
	re := regexp.MustCompile(`^(\d+)/(\w+)\s+(\w+)`)
	for _, line := range lines {
		matches := re.FindStringSubmatch(line)
		if len(matches) == 4 {
			num, _ := strconv.Atoi(matches[1])
			proto := matches[2]
			state := matches[3]

			if state == "open" {
				openCount++
			} else if state == "filtered" {
				filteredCount++
			}

			ports = append(ports, Port{
				Number: num,
				State:  state,
				Proto:  proto,
			})
		}
	}

	if filteredCount > 0 && openCount == 0 {
		firewall = true
	}

	openPorts := []Port{}
	for _, p := range ports {
		if p.State == "open" {
			openPorts = append(openPorts, p)
		}
	}

	return firewall, openPorts
}

func processHost(host *Host, board *StatusBoard) {
	if !host.Active {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), hostTimeout)
	defer cancel()

	board.Start(host)

	outputTop, err := runNmap(ctx, host.IP, "-Pn", "-T4", "--top-ports", "1000", "--open")
	if ctx.Err() != nil {
		board.Timeout(host)
		return
	}
	if err == nil {
		_, ports := parseNmapOutput(outputTop)
		host.Ports = ports
	}

	if len(host.Ports) == 0 {
		for _, evade := range evadeScans {
			if ctx.Err() != nil {
				board.Timeout(host)
				return
			}
			outputEvade, err := runNmap(ctx, host.IP, evade.Args...)
			if ctx.Err() != nil {
				board.Timeout(host)
				return
			}
			if err == nil {
				_, portsEvade := parseNmapOutput(outputEvade)
				if len(portsEvade) > 0 {
					host.Ports = portsEvade
					host.Evasion = strings.Join(evade.Args, " ")
					break
				}
			}
		}
		if len(host.Ports) == 0 {
			host.Firewall = true
		}
	}

	board.Finish(host)
}

func main() {
	parentDir := getParentDir()
	jsonDir := filepath.Join(parentDir, "json")
	inputFile := filepath.Join(jsonDir, "hosts-s1.json")
	outputFile := filepath.Join(jsonDir, "hosts-s2.json")

	if _, err := os.Stat(jsonDir); os.IsNotExist(err) {
		if err := os.MkdirAll(jsonDir, 0755); err != nil {
			fmt.Println("Erro ao criar diretório json:", err)
			return
		}
	}

	data, err := ioutil.ReadFile(inputFile)
	if err != nil {
		fmt.Println("Erro ao ler arquivo:", err)
		os.Exit(1)
	}

	var hosts []Host
	if err := json.Unmarshal(data, &hosts); err != nil {
		fmt.Println("Erro ao parsear JSON:", err)
		os.Exit(1)
	}

	fmt.Printf("Carregados %d hosts do arquivo JSON\n\n", len(hosts))

	board := NewStatusBoard()
	var wg sync.WaitGroup
	sem := make(chan struct{}, 5)
	activeCount := 0

	for i := range hosts {
		if hosts[i].Active {
			activeCount++
			wg.Add(1)
			go func(h *Host) {
				defer wg.Done()
				sem <- struct{}{}
				processHost(h, board)
				<-sem
			}(&hosts[i])
		}
	}

	fmt.Printf("Iniciando scans para %d hosts ativos (timeout: %s por host)...\n\n", activeCount, hostTimeout)
	wg.Wait()

	outJSON, _ := json.MarshalIndent(hosts, "", "  ")
	if err := ioutil.WriteFile(outputFile, outJSON, 0644); err != nil {
		fmt.Println("Erro ao salvar JSON:", err)
	}

	fmt.Printf("\nScan completo. Resultado salvo em %s\n", outputFile)

	openPortsCount := 0
	firewallCount := 0
	timedOutCount := 0
	for _, host := range hosts {
		if host.Firewall {
			firewallCount++
		}
		openPortsCount += len(host.Ports)
	}
	board.mu.Lock()
	timedOutCount = len(board.timedOut)
	board.mu.Unlock()

	fmt.Printf("\nEstatísticas:\n")
	fmt.Printf("- Total de hosts: %d\n", len(hosts))
	fmt.Printf("- Hosts ativos: %d\n", activeCount)
	fmt.Printf("- Hosts com firewall detectado: %d\n", firewallCount)
	fmt.Printf("- Hosts ignorados por timeout: %d\n", timedOutCount)
	fmt.Printf("- Total de portas abertas encontradas: %d\n", openPortsCount)
}
