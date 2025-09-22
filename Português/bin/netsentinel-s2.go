package main

import (
	"bytes"
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
)

type Port struct {
	Number int    `json:"number"`
	State  string `json:"state"`
	Proto  string `json:"proto"`
}

type Host struct {
	IP         string `json:"ip"`
	Hostname   string `json:"hostname"`
	Active     bool   `json:"active"`
	IsLocal    bool   `json:"is_local"`
	IsGateway  bool   `json:"is_gateway"`
	Firewall   bool   `json:"firewall,omitempty"`
	Ports      []Port `json:"ports,omitempty"`
	Evasion    string `json:"evasion,omitempty"`
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

type StatusBoard struct {
	mu         sync.Mutex
	inProgress map[string]string
	finished   map[string]string
}

func NewStatusBoard() *StatusBoard {
	return &StatusBoard{
		inProgress: make(map[string]string),
		finished:   make(map[string]string),
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

func (s *StatusBoard) render() {
	
	fmt.Print("\033[H\033[2J")
	fmt.Println("Hosts em progresso:")
	for _, h := range s.inProgress {
		fmt.Println(" -", h)
	}
	fmt.Println("\nHosts finalizados:")
	for _, h := range s.finished {
		fmt.Println(" -", h)
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
	currentDir := getCurrentDir()
	return filepath.Dir(currentDir)
}

func runNmap(ip string, args ...string) (string, error) {
	cmdArgs := append(args, ip)
	cmd := exec.Command("nmap", cmdArgs...)
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

	board.Start(host)

	outputTop, _ := runNmap(host.IP, "-Pn", "-T4", "--top-ports", "1000", "--open")
	_, ports := parseNmapOutput(outputTop)
	host.Ports = ports

	if len(host.Ports) == 0 {
		for _, evade := range evadeScans {
			outputEvade, _ := runNmap(host.IP, evade.Args...)
			_, portsEvade := parseNmapOutput(outputEvade)
			if len(portsEvade) > 0 {
				host.Ports = portsEvade
				host.Evasion = strings.Join(evade.Args, " ")
				break
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
	inputFile := filepath.Join(jsonDir, "hosts.json")
	outputFile := filepath.Join(jsonDir, "hosts-scanned.json")

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

	fmt.Printf("Iniciando scans para %d hosts ativos...\n\n", activeCount)
	wg.Wait()

	outJSON, _ := json.MarshalIndent(hosts, "", "  ")
	if err := ioutil.WriteFile(outputFile, outJSON, 0644); err != nil {
		fmt.Println("Erro ao salvar JSON:", err)
	}

	fmt.Printf("\nScan completo. Resultado salvo em %s\n", outputFile)

	openPortsCount := 0
	firewallCount := 0
	for _, host := range hosts {
		if host.Firewall {
			firewallCount++
		}
		openPortsCount += len(host.Ports)
	}

	fmt.Printf("\nEstatísticas:\n")
	fmt.Printf("- Total de hosts: %d\n", len(hosts))
	fmt.Printf("- Hosts ativos: %d\n", activeCount)
	fmt.Printf("- Hosts com firewall detectado: %d\n", firewallCount)
	fmt.Printf("- Total de portas abertas encontradas: %d\n", openPortsCount)
}