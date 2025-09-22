package main

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sort"
	"time"
	"path/filepath"
)

type Port struct {
	Number int    `json:"number"`
	State  string `json:"state"`
	Proto  string `json:"proto"`
}

type Host struct {
	IP          string                   `json:"ip"`
	Hostname    string                   `json:"hostname"`
	Active      bool                     `json:"active"`
	Is_local    bool                     `json:"is_local,omitempty"`
	Is_gateway  bool                     `json:"is_gateway,omitempty"`
	Firewall    bool                     `json:"firewall,omitempty"`
	Ports       []Port                   `json:"ports,omitempty"`
	RTT         float64                  `json:"rtt_ms,omitempty"`
	Fingerprint map[string]interface{}   `json:"fingerprint,omitempty"`
	Findings    []map[string]interface{} `json:"findings,omitempty"`
	Evasion     string                   `json:"evasion,omitempty"`
}

type Output struct {
	Hosts  []Host                   `json:"hosts"`
	Routes []Route                  `json:"routes"`
	Meta   map[string]interface{}   `json:"meta"`
}

type Route struct {
	From     string   `json:"from"`
	To       string   `json:"to"`
	Path     []string `json:"path"`
	Cost     float64  `json:"cost"`
	BestPath bool     `json:"best_path,omitempty"` 
}

var (
	enableFuzz      bool
	outFile         string
	httpTimeout     = 6 * time.Second
	connectTimeout  = 3 * time.Second
	maxConcurrency  = 12
	dirWordlist     = []string{
		"admin", "login", "dashboard", "api", "config", "debug", "backup", "server-status", "robots.txt", ".env",
	}
)

func main() {
	
	flag.BoolVar(&enableFuzz, "x", false, "Enable fuzzing (light)")
	flag.Parse()

	parentDir := getParentDir()
	jsonDir := filepath.Join(parentDir, "json")
	inputPath := filepath.Join(jsonDir, "hosts-scanned.json") 

	outFile = filepath.Join(jsonDir, "hosts-astar.json") 
	if ev := os.Getenv("NETSENTINEL_OUT"); ev != "" {
		outFile = ev
	}

	if _, err := os.Stat(jsonDir); os.IsNotExist(err) {
		if err := os.MkdirAll(jsonDir, 0755); err != nil {
			fmt.Printf("Erro ao criar diretório json: %v\n", err)
			os.Exit(1)
		}
	}

	raw, err := ioutil.ReadFile(inputPath)
	if err != nil {
		fmt.Printf("Erro lendo input JSON (%s): %v\n", inputPath, err)
		os.Exit(1)
	}

	var hosts []Host
	if err := json.Unmarshal(raw, &hosts); err != nil {
		fmt.Printf("Erro parseando JSON: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("\n[*] Fingerprinting e medição RTT (via TCP dial)...")
	fingerprintConcur(&hosts)

	fmt.Println("\n[*] Construindo rotas A* entre hosts ativos...")
	routes := computeAllPairsRoutes(hosts)

	if enableFuzz {
		fmt.Println("\n[*] Fuzzing ativado (-x), rodando fuzzing leve em portas web...")
		runFuzzing(&hosts)
	} else {
		fmt.Println("\n[*] Fuzzing não solicitado. Pulando etapa de fuzz.")
	}

	out := Output{
		Hosts:  hosts,
		Routes: routes,
		Meta: map[string]interface{}{
			"scanned_at": time.Now().UTC().Format(time.RFC3339),
			"flags": map[string]interface{}{
				"fuzzing": enableFuzz,
			},
		},
	}

	js, _ := json.MarshalIndent(out, "", "  ")
	if err := ioutil.WriteFile(outFile, js, 0644); err != nil {
		fmt.Printf("Erro salvando output: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("\n[+] Finalizado, output salvo em %s\n", outFile)
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

func fingerprintConcur(hosts *[]Host) {
	var wg sync.WaitGroup
	sem := make(chan struct{}, maxConcurrency)
	for i := range *hosts {
		wg.Add(1)
		sem <- struct{}{}
		go func(h *Host) {
			defer wg.Done()
			defer func(){ <-sem }()
			measureRTTAndBanner(h)
		}(&(*hosts)[i])
	}
	wg.Wait()
}

func measureRTTAndBanner(h *Host) {
	
	if len(h.Ports) == 0 {
		return
	}
	for _, p := range h.Ports {
		if p.State != "open" {
			continue
		}
		addr := net.JoinHostPort(h.IP, strconv.Itoa(p.Number))
		start := time.Now()
		conn, err := net.DialTimeout("tcp", addr, connectTimeout)
		if err != nil {
			continue
		}
		rtt := time.Since(start).Seconds() * 1000.0
		h.RTT = rtt
		
		conn.SetReadDeadline(time.Now().Add(800 * time.Millisecond))
		b := make([]byte, 512)
		n, _ := conn.Read(b)
		_ = conn.Close()
		banner := strings.TrimSpace(string(b[:n]))
		h.Fingerprint = map[string]interface{}{
			"first_open_port": p.Number,
			"banner_len":      len(banner),
		}
		
		if p.Number == 443 || p.Number == 8443 {
			if cn := getTLSSubjectCN(h.IP, p.Number); cn != "" {
				h.Fingerprint["tls_cn"] = cn
			}
		}
		return
	}
}

func getTLSSubjectCN(ip string, port int) string {
	addr := net.JoinHostPort(ip, strconv.Itoa(port))
	dialer := &net.Dialer{Timeout: connectTimeout}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		return ""
	}
	defer conn.Close()
	if len(conn.ConnectionState().PeerCertificates) > 0 {
		cert := conn.ConnectionState().PeerCertificates[0]
		return cert.Subject.CommonName
	}
	return ""
}

func computeAllPairsRoutes(hosts []Host) []Route {
	
	var localHost Host
	localIP := getLocalIP()
	foundLocal := false
	
	for _, h := range hosts {
		if h.Is_local {
			localHost = h
			foundLocal = true
			break
		}
	}
	
	if !foundLocal {
		for _, h := range hosts {
			if h.IP == localIP {
				localHost = h
				foundLocal = true
				break
			}
		}
	}
	
	if !foundLocal {
		localHost = Host{
			IP:       localIP,
			Hostname: "local",
			Active:   true,
			Is_local: true,
			RTT:      0,
		}
	}

	var routes []Route

	type hostCost struct {
		host Host
		cost float64
	}
	
	var targetHosts []hostCost
	
	for _, target := range hosts {
		if target.IP == localHost.IP || target.Is_local || !target.Active { 
			continue
		}
		
		cost := costBetween(localHost, target)
		targetHosts = append(targetHosts, hostCost{target, cost})

		routes = append(routes, Route{
			From: localHost.IP,
			To:   target.IP,
			Path: []string{localHost.IP, target.IP},
			Cost: cost,
		})
	}
	
	sort.Slice(targetHosts, func(i, j int) bool {
		return targetHosts[i].cost < targetHosts[j].cost
	})
	
	if len(targetHosts) > 0 {
		path := []string{localHost.IP}
		totalCost := 0.0
		
		for _, hc := range targetHosts {
			path = append(path, hc.host.IP)
			totalCost += hc.cost
		}
		
		routes = append(routes, Route{
			From: localHost.IP,
			To:   targetHosts[len(targetHosts)-1].host.IP,
			Path: path,
			Cost: totalCost,
		})
	}
	
	routes = markBestPaths(routes)
	
	return routes
}

func markBestPaths(routes []Route) []Route {
	
	for i := range routes {
		if len(routes[i].Path) > 2 {
			routes[i].BestPath = true
			break 
		}
	}
	return routes
}

func aStarPath(src Host, dst Host, allHosts []Host) ([]string, float64) {
	
	neighbors := make(map[string]Host)
	for _, h := range allHosts {
		neighbors[h.IP] = h
	}
	
	if _, ok := neighbors[src.IP]; !ok {
		neighbors[src.IP] = src
	}

	start := src.IP
	goal := dst.IP

	type nodeState struct {
		ip string
		g float64 
		f float64 
		parent string
	}

	open := map[string]*nodeState{}
	closed := map[string]bool{}

	h0 := heuristicIP(start, goal)
	open[start] = &nodeState{ip:start, g:0, f:h0, parent:""}

	for len(open) > 0 {
		
		var current *nodeState
		var curKey string
		for k, v := range open {
			if current == nil || v.f < current.f {
				current = v
				curKey = k
			}
		}
		if current.ip == goal {
			
			path := []string{}
			c := current
			for c != nil {
				path = append([]string{c.ip}, path...)
				if c.parent == "" {
					break
				}
				p := open[c.parent]
				if p == nil {
					
					break
				}
				c = p
			}
			
			reconstructed, cost := reconstructGreedyPath(start, goal, neighbors)
			return reconstructed, cost
		}

		delete(open, curKey)
		closed[current.ip] = true

		for nid, nHost := range neighbors {
			if closed[nid] {
				continue
			}
			edgeCost := costBetween(neighbors[current.ip], nHost)
			tentativeG := current.g + edgeCost
			if existing, ok := open[nid]; !ok || tentativeG < existing.g {
				h := heuristicIP(nid, goal)
				open[nid] = &nodeState{ip: nid, g: tentativeG, f: tentativeG + h, parent: current.ip}
			}
		}
	}

	return []string{start, goal}, costBetween(src, dst)
}

func heuristicIP(a, b string) float64 {
	ai := ipToUint32(a)
	bi := ipToUint32(b)
	dist := float64(absInt64(int64(ai) - int64(bi)))
	
	return dist / 256.0
}

func absInt64(x int64) int64 {
	if x < 0 { return -x }
	return x
}

func ipToUint32(ipstr string) uint32 {
	ip := net.ParseIP(ipstr)
	if ip == nil {
		return 0
	}
	ip = ip.To4()
	if ip == nil {
		return 0
	}
	return binary.BigEndian.Uint32(ip)
}

func isWebPort(p int) bool {
	switch p {
	case 80, 443, 8080, 8000, 8443:
		return true
	default:
		return false
	}
}

func costBetween(u, v Host) float64 {
	baseCost := 20.0
	adjustment := 0.0

	if u.RTT > 0 && v.RTT > 0 {
		adjustment += (u.RTT + v.RTT) / 10.0 
	} else if u.RTT > 0 {
		adjustment += u.RTT / 5.0
	} else if v.RTT > 0 {
		adjustment += v.RTT / 5.0
	}

	if v.Firewall {
		adjustment += 15.0 
	}
	
	if !v.Active {
		adjustment += 30.0 
	}

	for _, p := range v.Ports {
		if p.State == "open" {
			switch {
			case isWebPort(p.Number):
				adjustment -= 20.0 
			case p.Number == 22:    
				adjustment -= 12.0
			case p.Number == 3389:  
				adjustment -= 15.0
			case p.Number == 445:   
				adjustment -= 14.0
			case p.Number == 21 || p.Number == 20:  
				adjustment -= 10.0
			case p.Number == 23:    
				adjustment -= 8.0
			default:
				adjustment -= 2.0   
			}
		}
	}

	ipDist := float64(absInt64(int64(ipToUint32(u.IP)) - int64(ipToUint32(v.IP))))
	adjustment += ipDist / (256.0 * 4.0) 

	total := baseCost + adjustment
	
	if total < 1.0 {
		total = 1.0
	}
	return total
}

func reconstructGreedyPath(start, goal string, nodes map[string]Host) ([]string, float64) {
	path := []string{start}
	curr := start
	total := 0.0
	visited := map[string]bool{start:true}
	for curr != goal {
		
		var best string
		bestScore := 1e18
		for ip, h := range nodes {
			if visited[ip] { continue }
			edge := costBetween(nodes[curr], h)
			hv := heuristicIP(ip, goal)
			score := edge + hv
			if score < bestScore {
				bestScore = score
				best = ip
			}
		}
		if best == "" {
			
			path = append(path, goal)
			total += costBetween(nodes[curr], nodes[goal])
			break
		}
		path = append(path, best)
		total += costBetween(nodes[curr], nodes[best])
		visited[best] = true
		curr = best
		
		if len(path) > 50 {
			path = append(path, goal)
			break
		}
	}
	return path, total
}

func runFuzzing(hosts *[]Host) {
	ctx := context.Background()
	sem := make(chan struct{}, maxConcurrency)
	var wg sync.WaitGroup
	for i := range *hosts {
		
		webPorts := webPortsOf((*hosts)[i])
		if len(webPorts) == 0 {
			continue
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(h *Host, ports []int) {
			defer wg.Done()
			defer func(){ <-sem }()
			runLightFuzzHost(ctx, h, ports)
		}(&(*hosts)[i], webPorts)
	}
	wg.Wait()
}

func webPortsOf(h Host) []int {
	var res []int
	for _, p := range h.Ports {
		if p.State == "open" && isWebPort(p.Number) {
			res = append(res, p.Number)
		}
	}
	return res
}

func runLightFuzzHost(ctx context.Context, h *Host, ports []int) {
	clientHTTP := &http.Client{ Timeout: httpTimeout }
	
	tlsTransport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	clientHTTPS := &http.Client{
		Timeout: httpTimeout,
		Transport: tlsTransport,
	}

	for _, port := range ports {
		baseURL := buildBaseURL(h.IP, port)
		
		probeURL := baseURL + "/"
		status, body, _ := doGet(probeURL, clientHTTP, clientHTTPS)
		h.Findings = append(h.Findings, map[string]interface{}{
			"type": "http-probe",
			"port": port,
			"url": probeURL,
			"status": status,
			"length": len(body),
		})
		
		for _, pth := range dirWordlist {
			url := strings.TrimRight(baseURL, "/") + "/" + pth
			st, b, _ := doGet(url, clientHTTP, clientHTTPS)
			
			if st == 200 || st == 301 || st == 302 || (len(b) > 50 && st >= 200 && st < 500) {
				h.Findings = append(h.Findings, map[string]interface{}{
					"type": "dir-discovery",
					"port": port,
					"url": url,
					"status": st,
					"length": len(b),
					"note": "likely resource discovered",
				})
			}
			
			time.Sleep(120 * time.Millisecond)
		}
		
		uniqueToken := fmt.Sprintf("nm-%d", time.Now().UnixNano())
		testURL := fmt.Sprintf("%s/?q=%s", baseURL, uniqueToken)
		st, b, _ := doGet(testURL, clientHTTP, clientHTTPS)
		if st >= 200 && strings.Contains(string(b), uniqueToken) {
			h.Findings = append(h.Findings, map[string]interface{}{
				"type": "param-reflection",
				"port": port,
				"url": testURL,
				"status": st,
				"proof": fmt.Sprintf("token %s reflected", uniqueToken),
			})
		}
	}
}

func buildBaseURL(ip string, port int) string {
	switch port {
	case 443, 8443:
		return fmt.Sprintf("https://%s:%d", ip, port)
	default:
		return fmt.Sprintf("http://%s:%d", ip, port)
	}
}

func doGet(url string, httpClient, httpsClient *http.Client) (int, []byte, error) {
	var cli *http.Client
	if strings.HasPrefix(url, "https://") {
		cli = httpsClient
	} else {
		cli = httpClient
	}

	req, err := http.NewRequestWithContext(context.Background(), "GET", url, nil)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("User-Agent", "netsentinel-stage3/1.0")

	resp, err := cli.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 65536)) // cap read
	return resp.StatusCode, body, nil
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