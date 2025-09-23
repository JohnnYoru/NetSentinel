package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode"
)

type Port struct {
	Number int    `json:"number"`
	State  string `json:"state"`
	Proto  string `json:"proto"`
}

type Finding struct {
	Length int    `json:"length"`
	Port   int    `json:"port,omitempty"`
	Status int    `json:"status,omitempty"`
	Type   string `json:"type"`
	URL    string `json:"url,omitempty"`
	Note   string `json:"note,omitempty"`
}

type Fingerprint struct {
	BannerLen     int `json:"banner_len"`
	FirstOpenPort int `json:"first_open_port"`
}

type AStarHost struct {
	IP          string       `json:"ip"`
	Hostname    string       `json:"hostname"`
	Active      bool         `json:"active"`
	IsLocal     bool         `json:"is_local,omitempty"`
	IsGateway   bool         `json:"is_gateway,omitempty"`
	Firewall    bool         `json:"firewall,omitempty"`
	Ports       []Port       `json:"ports,omitempty"`
	Evasion     string       `json:"evasion,omitempty"`
	RttMs       float64      `json:"rtt_ms,omitempty"`
	Fingerprint Fingerprint  `json:"fingerprint,omitempty"`
	Findings    []Finding    `json:"findings,omitempty"`
}

type Route struct {
	From     string   `json:"from"`
	To       string   `json:"to"`
	Path     []string `json:"path"`
	Cost     float64  `json:"cost"`
	BestPath bool     `json:"best_path,omitempty"`
}

type Meta struct {
	Flags struct {
		Fuzzing bool `json:"fuzzing"`
	} `json:"flags"`
	ScannedAt string `json:"scanned_at"`
}

type AStarData struct {
	Hosts  []AStarHost `json:"hosts"`
	Routes []Route     `json:"routes"`
	Meta   Meta        `json:"meta"`
}

type CytoscapeNode struct {
	Data NodeData `json:"data"`
}

type CytoscapeEdge struct {
	Data EdgeData `json:"data"`
}

type NodeData struct {
	ID          string       `json:"id"`
	Label       string       `json:"label"`
	IP          string       `json:"ip,omitempty"`
	Hostname    string       `json:"hostname,omitempty"`
	Type        string       `json:"type"`
	Active      bool         `json:"active,omitempty"`
	Gateway     bool         `json:"gateway,omitempty"`
	Local       bool         `json:"local,omitempty"`
	Firewall    bool         `json:"firewall,omitempty"`
	Ports       []Port       `json:"ports,omitempty"`
	Evasion     string       `json:"evasion,omitempty"`
	Findings    []Finding    `json:"findings,omitempty"`
	RttMs       float64      `json:"rtt_ms,omitempty"`
	Fingerprint Fingerprint  `json:"fingerprint,omitempty"`
	OpenPorts   int          `json:"open_ports,omitempty"`
	TCPPorts    int          `json:"tcp_ports,omitempty"`
	UDPPorts    int          `json:"udp_ports,omitempty"`
	WebFindings int          `json:"web_findings,omitempty"`
	Cost        float64      `json:"cost,omitempty"`
	Status      int          `json:"status,omitempty"`
	PortNumber  int          `json:"port_number,omitempty"`
	Protocol    string       `json:"protocol,omitempty"`
	URL         string       `json:"url,omitempty"`
}

type EdgeData struct {
	ID         string  `json:"id"`
	Source     string  `json:"source"`
	Target     string  `json:"target"`
	Label      string  `json:"label,omitempty"`
	Cost       float64 `json:"cost,omitempty"`
	IsBestPath bool    `json:"is_best_path,omitempty"`
	IsDirect   bool    `json:"is_direct,omitempty"`
	IsPort     bool    `json:"is_port,omitempty"`
	IsDir      bool    `json:"is_dir,omitempty"`
	Color      string  `json:"color,omitempty"`
}

type CytoscapeLayers struct {
	Overview struct {
		Nodes []CytoscapeNode `json:"nodes"`
		Edges []CytoscapeEdge `json:"edges"`
	} `json:"overview"`
	Bestpath struct {
		Nodes []CytoscapeNode `json:"nodes"`
		Edges []CytoscapeEdge `json:"edges"`
	} `json:"bestpath"`
	Direct struct {
		Nodes []CytoscapeNode `json:"nodes"`
		Edges []CytoscapeEdge `json:"edges"`
	} `json:"direct"`
	Meta Meta `json:"meta"`
}

func getCurrentDir() string {
	dir, err := os.Getwd()
	if err != nil {
		return "." // fallback
	}
	return dir
}

func getParentDir() string {
	currentDir := getCurrentDir()
	return filepath.Dir(currentDir)
}

func main() {

	parentDir := getParentDir()
	jsonDir := filepath.Join(parentDir, "json")
	cytoDir := filepath.Join(parentDir, "cyto")

	inputFile := filepath.Join(jsonDir, "hosts-s3.json")

	var outputFile string
	outputFile = filepath.Join(cytoDir, "cyto-graph.json")
	if ev := os.Getenv("NETSENTINEL_OUT"); ev != "" {
		outputFile = ev
	}

	fileContent, err := os.ReadFile(inputFile)
	if err != nil {
		fmt.Printf("Erro ao ler arquivo %s: %v\n", inputFile, err)
		return
	}

	var astarData AStarData
	err = json.Unmarshal(fileContent, &astarData)
	if err != nil {
		fmt.Printf("Erro ao fazer parse do JSON: %v\n", err)
		return
	}

	graph := convertToCytoscapeLayers(astarData)

	outputJSON, err := json.MarshalIndent(graph, "", "  ")
	if err != nil {
		fmt.Printf("Erro ao converter para JSON: %v\n", err)
		return
	}

	err = os.MkdirAll(filepath.Dir(outputFile), 0755)
	if err != nil {
		fmt.Printf("Erro ao criar diretório: %v\n", err)
		return
	}

	err = os.WriteFile(outputFile, outputJSON, 0644)
	if err != nil {
		fmt.Printf("Erro ao escrever arquivo %s: %v\n", outputFile, err)
		return
	}

	fmt.Printf("Arquivo convertido com sucesso: %s\n", outputFile)
	fmt.Printf("Visão Geral: %d nós, %d arestas\n", len(graph.Overview.Nodes), len(graph.Overview.Edges))
	fmt.Printf("Melhor Path: %d nós, %d arestas\n", len(graph.Bestpath.Nodes), len(graph.Bestpath.Edges))
	fmt.Printf("Conexões Diretas: %d nós, %d arestas\n", len(graph.Direct.Nodes), len(graph.Direct.Edges))
}

func convertToCytoscapeLayers(astarData AStarData) CytoscapeLayers {
	var layers CytoscapeLayers
	layers.Meta = astarData.Meta

	localHost := findLocalHost(astarData.Hosts)
	gatewayHost := findGatewayHost(astarData.Hosts)
	activeHosts := findActiveHosts(astarData.Hosts)
	inactiveHosts := findInactiveHosts(astarData.Hosts)
	bestMultiHopRoute := findBestMultiHopRoute(astarData.Routes)

	layers.Overview.Nodes, layers.Overview.Edges = createOverviewLayer(localHost, gatewayHost, activeHosts, inactiveHosts)

	layers.Bestpath.Nodes, layers.Bestpath.Edges = createBestpathLayer(bestMultiHopRoute, astarData.Hosts, astarData.Routes)

	layers.Direct.Nodes, layers.Direct.Edges = createDirectConnectionsLayer(localHost, gatewayHost, activeHosts, astarData.Routes)

	return layers
}

func findLocalHost(hosts []AStarHost) *AStarHost {
	for i := range hosts {
		if hosts[i].IsLocal {
			return &hosts[i]
		}
	}
	return nil
}

func findGatewayHost(hosts []AStarHost) *AStarHost {
	for i := range hosts {
		if hosts[i].IsGateway {
			return &hosts[i]
		}
	}
	return nil
}

func findActiveHosts(hosts []AStarHost) []AStarHost {
	var active []AStarHost
	for _, host := range hosts {
		if host.Active && !host.IsLocal && !host.IsGateway {
			active = append(active, host)
		}
	}
	return active
}

func findInactiveHosts(hosts []AStarHost) []AStarHost {
	var inactive []AStarHost
	for _, host := range hosts {
		if !host.Active && !host.IsLocal && !host.IsGateway {
			inactive = append(inactive, host)
		}
	}
	return inactive
}

func findBestMultiHopRoute(routes []Route) *Route {
	var best *Route
	for i := range routes {
		
		if routes[i].BestPath {
			best = &routes[i]
			break
		}
	}

	if best == nil {
		for i := range routes {
			if len(routes[i].Path) > 2 {
				if best == nil || len(routes[i].Path) > len(best.Path) {
					best = &routes[i]
				}
			}
		}
	}
	return best
}

func getColorByCost(cost float64) string {
	if cost < 10 {
		return "#4fc3f7" 
	} else if cost < 30 {
		return "#7cb342" 
	} else if cost < 50 {
		return "#ffb74d" 
	} else if cost < 70 {
		return "#ff9800" 
	}
	return "#e57373" 
}

func hasWebPorts(ports []Port) bool {
	webPorts := map[int]bool{80: true, 443: true, 8080: true, 8000: true, 8443: true}
	for _, port := range ports {
		if port.Proto == "tcp" && webPorts[port.Number] && port.State == "open" {
			return true
		}
	}
	return false
}

func getValidFindings(findings []Finding) []Finding {
	var valid []Finding
	invalidStatus := map[int]bool{401: true, 402: true, 403: true}
	for _, finding := range findings {
		if (finding.Type == "http-probe" || finding.Type == "dir-discovery") &&
			!invalidStatus[finding.Status] {
			valid = append(valid, finding)
		}
	}
	return valid
}

func countPortTypes(ports []Port) (tcpCount int, udpCount int) {
	for _, port := range ports {
		if port.Proto == "tcp" {
			tcpCount++
		} else if port.Proto == "udp" {
			udpCount++
		}
	}
	return tcpCount, udpCount
}

func countWebFindings(findings []Finding) int {
	count := 0
	for _, finding := range findings {
		if finding.Type == "http-probe" || finding.Type == "dir-discovery" {
			count++
		}
	}
	return count
}

func getDirFromURL(url string) string {
	parts := strings.Split(url, "/")
	if len(parts) >= 4 {
		return "/" + parts[3]
	}
	return url
}

func capitalizeHostname(h string) string {
    if h == "" {
        return h
    }
    
    for _, r := range h {
        if unicode.IsUpper(r) {
            return h
        }
    }

    seps := func(r rune) bool {
        return r == '-' || r == '.' || r == '_' || unicode.IsSpace(r)
    }
    parts := strings.FieldsFunc(h, seps)
    for i, p := range parts {
        if p == "" {
            continue
        }
        r := []rune(p)
        r[0] = unicode.ToUpper(r[0])
        for j := 1; j < len(r); j++ {
            r[j] = unicode.ToLower(r[j])
        }
        parts[i] = string(r)
    }
    return strings.Join(parts, " ")
}

func createOverviewLayer(localHost, gatewayHost *AStarHost, activeHosts, inactiveHosts []AStarHost) ([]CytoscapeNode, []CytoscapeEdge) {
	var nodes []CytoscapeNode
	var edges []CytoscapeEdge

	if localHost != nil {
		tcpPorts, udpPorts := countPortTypes(localHost.Ports)
		webFindings := countWebFindings(localHost.Findings)

		nodes = append(nodes, CytoscapeNode{
			Data: NodeData{
				ID:          localHost.IP,
				Label:       capitalizeHostname(localHost.Hostname),
				IP:          localHost.IP,
				Hostname:    capitalizeHostname(localHost.Hostname),
				Type:        "local",
				Active:      localHost.Active,
				Local:       localHost.IsLocal,
				Ports:       localHost.Ports,
				Evasion:     localHost.Evasion,
				Findings:    localHost.Findings,
				RttMs:       localHost.RttMs,
				Fingerprint: localHost.Fingerprint,
				OpenPorts:   len(localHost.Ports),
				TCPPorts:    tcpPorts,
				UDPPorts:    udpPorts,
				WebFindings: webFindings,
			},
		})
	}

	if gatewayHost != nil {
		tcpPorts, udpPorts := countPortTypes(gatewayHost.Ports)
		webFindings := countWebFindings(gatewayHost.Findings)

		nodes = append(nodes, CytoscapeNode{
			Data: NodeData{
				ID:          gatewayHost.IP,
				Label:       capitalizeHostname(gatewayHost.Hostname),
				IP:          gatewayHost.IP,
				Hostname:    capitalizeHostname(gatewayHost.Hostname),
				Type:        "gateway",
				Active:      gatewayHost.Active,
				Gateway:     gatewayHost.IsGateway,
				Ports:       gatewayHost.Ports,
				Findings:    gatewayHost.Findings,
				RttMs:       gatewayHost.RttMs,
				Fingerprint: gatewayHost.Fingerprint,
				OpenPorts:   len(gatewayHost.Ports),
				TCPPorts:    tcpPorts,
				UDPPorts:    udpPorts,
				WebFindings: webFindings,
			},
		})
	}

	activeGroupID := "ativos"
	nodes = append(nodes, CytoscapeNode{
		Data: NodeData{
			ID:    activeGroupID,
			Label: "Hosts Ativos",
			Type:  "group",
		},
	})

	inactiveGroupID := "inativos"
	nodes = append(nodes, CytoscapeNode{
		Data: NodeData{
			ID:    inactiveGroupID,
			Label: "Hosts Inativos",
			Type:  "group",
		},
	})

	for _, host := range activeHosts {
		tcpPorts, udpPorts := countPortTypes(host.Ports)
		webFindings := countWebFindings(host.Findings)

		nodes = append(nodes, CytoscapeNode{
			Data: NodeData{
				ID:          host.IP,
				Label:       capitalizeHostname(host.Hostname),
				IP:          host.IP,
				Hostname:    capitalizeHostname(host.Hostname),
				Type:        "host",
				Active:      host.Active,
				Firewall:    host.Firewall,
				Ports:       host.Ports,
				Evasion:     host.Evasion,
				Findings:    host.Findings,
				RttMs:       host.RttMs,
				Fingerprint: host.Fingerprint,
				OpenPorts:   len(host.Ports),
				TCPPorts:    tcpPorts,
				UDPPorts:    udpPorts,
				WebFindings: webFindings,
			},
		})
	}

	for _, host := range inactiveHosts {
		nodes = append(nodes, CytoscapeNode{
			Data: NodeData{
				ID:       host.IP,
				Label:    capitalizeHostname(host.Hostname),
				IP:       host.IP,
				Hostname: capitalizeHostname(host.Hostname),
				Type:     "host-inactive",
				Active:   host.Active,
			},
		})
	}

	if localHost != nil && gatewayHost != nil {
		edges = append(edges, CytoscapeEdge{
			Data: EdgeData{
				ID:     fmt.Sprintf("local-to-gateway-%s", gatewayHost.IP),
				Source: localHost.IP,
				Target: gatewayHost.IP,
			},
		})
	}

	if gatewayHost != nil {
		
		edges = append(edges, CytoscapeEdge{
			Data: EdgeData{
				ID:     "gateway-to-ativos",
				Source: gatewayHost.IP,
				Target: activeGroupID,
			},
		})

		edges = append(edges, CytoscapeEdge{
			Data: EdgeData{
				ID:     "gateway-to-inativos",
				Source: gatewayHost.IP,
				Target: inactiveGroupID,
			},
		})
	}

	for _, host := range activeHosts {
		edges = append(edges, CytoscapeEdge{
			Data: EdgeData{
				ID:     fmt.Sprintf("ativos-to-%s", host.IP),
				Source: activeGroupID,
				Target: host.IP,
			},
		})
	}

	for _, host := range inactiveHosts {
		edges = append(edges, CytoscapeEdge{
			Data: EdgeData{
				ID:     fmt.Sprintf("inativos-to-%s", host.IP),
				Source: inactiveGroupID,
				Target: host.IP,
			},
		})
	}

	return nodes, edges
}

func createBestpathLayer(bestRoute *Route, hosts []AStarHost, allRoutes []Route) ([]CytoscapeNode, []CytoscapeEdge) {
    var nodes []CytoscapeNode
    var edges []CytoscapeEdge

    if bestRoute == nil {
        return nodes, edges
    }

    for _, ip := range bestRoute.Path {
        for _, host := range hosts {
            if host.IP == ip {
                tcpPorts, udpPorts := countPortTypes(host.Ports)
                webFindings := countWebFindings(host.Findings)

                nodeType := "host"
                if host.IsLocal {
                    nodeType = "local"
                } else if host.IsGateway {
                    nodeType = "gateway"
                }

                nodes = append(nodes, CytoscapeNode{
                    Data: NodeData{
                        ID:          host.IP,
                        Label:       capitalizeHostname(host.Hostname),
                        IP:          host.IP,
                        Hostname:    capitalizeHostname(host.Hostname),
                        Type:        nodeType,
                        Active:      host.Active,
                        Local:       host.IsLocal,
                        Gateway:     host.IsGateway,
                        Firewall:    host.Firewall,
                        Ports:       host.Ports,
                        Evasion:     host.Evasion,
                        Findings:    host.Findings,
                        RttMs:       host.RttMs,
                        Fingerprint: host.Fingerprint,
                        OpenPorts:   len(host.Ports),
                        TCPPorts:    tcpPorts,
                        UDPPorts:    udpPorts,
                        WebFindings: webFindings,
                    },
                })
                break
            }
        }
    }

    for i := 0; i < len(bestRoute.Path)-1; i++ {
        source := bestRoute.Path[i]
        target := bestRoute.Path[i+1]

        var hopCost float64
        for _, r := range allRoutes {
            if r.From == bestRoute.From && r.To == target {
                hopCost = r.Cost
                break
            }
        }

        edges = append(edges, CytoscapeEdge{
            Data: EdgeData{
                ID:         fmt.Sprintf("bestpath-%s-%s", source, target),
                Source:     source,
                Target:     target,
                Label:      fmt.Sprintf("Cost: %.2f", hopCost),
                Cost:       hopCost,
                IsBestPath: true,
                Color:      getColorByCost(hopCost),
            },
        })
    }

    return nodes, edges
}

func createDirectConnectionsLayer(localHost *AStarHost, gatewayHost *AStarHost, activeHosts []AStarHost, routes []Route) ([]CytoscapeNode, []CytoscapeEdge) {
	var nodes []CytoscapeNode
	var edges []CytoscapeEdge

	if localHost == nil {
		return nodes, edges
	}

	tcpPorts, udpPorts := countPortTypes(localHost.Ports)
	webFindings := countWebFindings(localHost.Findings)

	nodes = append(nodes, CytoscapeNode{
		Data: NodeData{
			ID:          localHost.IP,
			Label:       capitalizeHostname(localHost.Hostname),
			IP:          localHost.IP,
			Hostname:    capitalizeHostname(localHost.Hostname),
			Type:        "local",
			Active:      localHost.Active,
			Local:       localHost.IsLocal,
			Ports:       localHost.Ports,
			Evasion:     localHost.Evasion,
			Findings:    localHost.Findings,
			RttMs:       localHost.RttMs,
			Fingerprint: localHost.Fingerprint,
			OpenPorts:   len(localHost.Ports),
			TCPPorts:    tcpPorts,
			UDPPorts:    udpPorts,
			WebFindings: webFindings,
		},
	})

	hostsToShow := activeHosts
	if gatewayHost != nil {
		
		found := false
		for _, h := range hostsToShow {
			if h.IP == gatewayHost.IP {
				found = true
				break
			}
		}
		if !found {
			hostsToShow = append(hostsToShow, *gatewayHost)
		}
	}

	for _, targetHost := range hostsToShow {
		
		var directRoute *Route
		for i := range routes {
			if routes[i].From == localHost.IP && routes[i].To == targetHost.IP && len(routes[i].Path) == 2 {
				directRoute = &routes[i]
				break
			}
		}

		tcpPorts, udpPorts := countPortTypes(targetHost.Ports)
		webFindings := countWebFindings(targetHost.Findings)

		nodeType := "host"
		if targetHost.IsGateway {
			nodeType = "gateway"
		} else if targetHost.IsLocal {
			nodeType = "local"
		}

		nodes = append(nodes, CytoscapeNode{
			Data: NodeData{
				ID:          targetHost.IP,
				Label:       capitalizeHostname(targetHost.Hostname),
				IP:          targetHost.IP,
				Hostname:    capitalizeHostname(targetHost.Hostname),
				Type:        nodeType,
				Active:      targetHost.Active,
				Local:       targetHost.IsLocal,
				Gateway:     targetHost.IsGateway,
				Firewall:    targetHost.Firewall,
				Ports:       targetHost.Ports,
				Evasion:     targetHost.Evasion,
				Findings:    targetHost.Findings,
				RttMs:       targetHost.RttMs,
				Fingerprint: targetHost.Fingerprint,
				OpenPorts:   len(targetHost.Ports),
				TCPPorts:    tcpPorts,
				UDPPorts:    udpPorts,
				WebFindings: webFindings,
			},
		})

		if directRoute != nil {
			edgeID := fmt.Sprintf("direct-%s-%s", localHost.IP, targetHost.IP)
			edges = append(edges, CytoscapeEdge{
				Data: EdgeData{
					ID:       edgeID,
					Source:   localHost.IP,
					Target:   targetHost.IP,
					Label:    fmt.Sprintf("Cost: %.2f", directRoute.Cost),
					Cost:     directRoute.Cost,
					IsDirect: true,
					Color:    getColorByCost(directRoute.Cost),
				},
			})
		} else {
			
			edgeID := fmt.Sprintf("direct-%s-%s", localHost.IP, targetHost.IP)
			edges = append(edges, CytoscapeEdge{
				Data: EdgeData{
					ID:       edgeID,
					Source:   localHost.IP,
					Target:   targetHost.IP,
					IsDirect: true,
				},
			})
		}

		for _, port := range targetHost.Ports {
			if port.State != "open" {
				continue
			}

			protoUpper := strings.ToUpper(port.Proto)
			portID := fmt.Sprintf("port-%d-%s", port.Number, targetHost.IP)
			nodes = append(nodes, CytoscapeNode{
				Data: NodeData{
					ID:         portID,
					Label:      fmt.Sprintf("%d (%s)", port.Number, protoUpper),
					Type:       "port",
					PortNumber: port.Number,
					Protocol:   protoUpper,
				},
			})

			edges = append(edges, CytoscapeEdge{
				Data: EdgeData{
					ID:     fmt.Sprintf("host-to-port-%s-%d", targetHost.IP, port.Number),
					Source: targetHost.IP,
					Target: portID,
					IsPort: true,
				},
			})

			if port.Proto == "tcp" && (port.Number == 80 || port.Number == 443 || port.Number == 8080 || port.Number == 8000 || port.Number == 8443) {
				validFindings := getValidFindings(targetHost.Findings)
				for _, finding := range validFindings {
					if finding.Port == port.Number {
						
						dirPath := strings.ReplaceAll(getDirFromURL(finding.URL), "/", "_")
						if dirPath == "" {
							dirPath = "root"
						}
						dirID := fmt.Sprintf("dir-%d-%s-%s", port.Number, dirPath, targetHost.IP)

						nodes = append(nodes, CytoscapeNode{
							Data: NodeData{
								ID:    dirID,
								Label: getDirFromURL(finding.URL),
								Type:  "directory",
								Status: finding.Status,
								URL:   finding.URL,
							},
						})

						edges = append(edges, CytoscapeEdge{
							Data: EdgeData{
								ID:     fmt.Sprintf("port-to-dir-%d-%s-%s", port.Number, dirPath, targetHost.IP),
								Source: portID,
								Target: dirID,
								IsDir:  true,
							},
						})
					}
				}
			}
		}
	}

	return nodes, edges
}