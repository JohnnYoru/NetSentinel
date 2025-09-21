# NeoSentinel
Network Recon &amp; Topology Mapping - Offensive

**NeoSentinel** is a comprehensive network scanning and visualization tool designed to map, analyze, and display local network topology, open ports, and service findings. It combines fast Go-based scanning utilities with a modern, interactive web visualization powered by Cytoscape.js.

---

## Features

- **Network Discovery:** Scans the local subnet to identify active hosts, gateways, and devices.  
- **Port Scanning:** Detects open TCP/UDP ports, firewalls, and applies evasion techniques for deeper analysis.  
- **Service Fingerprinting:** Gathers banners and probes HTTP services for directories and endpoints.  
- **Pathfinding:** Calculates optimal and multi-hop routes between hosts.  
- **Interactive Visualization:** Presents network topology, best paths, and direct connections in a beautiful web UI.  
- **Exportable Results:** Saves scan data and visual graphs in structured JSON for further analysis.  

---

## Project Structure

- `neosentinel-s1.go`: Scans the subnet for active hosts.  
- `neosentinel-s2.go`: Scans open ports and applies evasion.
- `neosentinel-s3.go`: Calculates optimal and multi-hop routes between hosts using.
- `neosentinel-s4.go`: Converts scan results to Cytoscape graph format.  
- `cyto.html`: Interactive web visualization.  
- `hosts.json`, `hosts_scanned.json`, `hosts-s3.json`: Scan and analysis outputs.  

---

## Usage

1. **Scan the Network**  
   Discovers hosts and saves results to `hosts.json`.  

2. **Scan Ports**  
   Scans open ports, applies evasion, and saves to `hosts_scanned.json`.  

3. **Generate Visualization Data**  
   Converts scan results to Cytoscape format in `hosts-s3.json`.  

4. **View the Network**  
   Open `cyto.html` in your browser to explore the network graph interactively.  

---

## Requirements

- Go (>=1.18)  
- nmap (for port scanning)  
- Modern Web Browser (for visualization)  
- Cytoscape.js (included via CDN in HTML)  

---

## Visualization Modes

- **Visão Geral:** Full network topology.  
- **Melhor Rota:** Best multi-hop path (A*).  
- **Conexões Diretas:** Direct host-to-host and port connections.  

---

## Customization

- Edit Go source files in `bin` to adjust scanning logic or output formats.  
- Modify `cyto.html` for UI/UX changes or additional visualization features.  

---

## Disclaimer

**Warning:** This tool is intended for **authorized testing, lab environments, and educational purposes only**. Unauthorized scanning or intrusion into networks or devices without explicit permission is **illegal** and can result in severe penalties. Use responsibly.  

---

## License

This project is licensed under the **MIT License**.  

---

## Author

Developed by **JohnnYoru**  
