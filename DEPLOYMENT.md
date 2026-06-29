# Ai-SOC.MSP Dashboard V2 — Deployment Guide

## Overview
FortiSIEM-style SOC Dashboard for Wazuh on port **8444** (HTTPS).
Runs alongside V1 (port 8443) and Zabbix Docker containers without conflicts.

**Login:** `admin` / `adminW@zuh`

## Components
- **A: SOC Dashboard** — Overview with incident counts, top attackers, trend chart, critical alerts
- **B: Incidents Explorer** — Stacked bar trend + 4-panel breakdown + filterable table
- **C: Incidents List** — Full table with severity summary, MITRE ATT&CK, status/resolution
- **D: CMDB/Devices** — Agent inventory with health overview, CPU/RAM bars, disk detail
- **ICMP Data** — ICMP monitoring events from the SNMP/ICMP wodle
- **SNMP Performance** — SNMP performance metrics from SNMP-enabled devices

## Prerequisites
- Wazuh Manager running with API on port 55000
- Wazuh Indexer (OpenSearch) on port 9200
- Docker and Docker Compose installed (already on the Azure VM for Zabbix)

---

## Option A: Docker Deploy (Recommended)

### 1. Upload files to server
```bash
# Upload the entire wazuh-soc-dashboard/ folder to your server:
scp -r wazuh-soc-dashboard/ root@<SERVER_IP>:/opt/wazuh-soc-dashboard/
```

### 2. Open port 8444
```bash
sudo ufw allow 8444/tcp
```
Also add Azure NSG rule: Destination port 8444, TCP, Allow.

### 3. Build and start the container
```bash
cd /opt/wazuh-soc-dashboard
docker compose up -d --build
```

### 4. Verify it's running
```bash
# Check container status
docker compose ps

# Check logs
docker compose logs -f

# Test login page
curl -sk https://127.0.0.1:8444/login | head -5
```

### 5. Access
```
https://azure-eos-wazuh.malaysiawest.cloudapp.azure.com:8444
```
Login: `admin` / `adminW@zuh`

### Docker Management Commands
```bash
# View logs
docker compose logs -f soc-dashboard

# Restart after code changes
docker compose up -d --build

# Stop
docker compose down

# Stop and remove data volume (reset passwords)
docker compose down -v
```

### Coexistence with Zabbix
This runs completely independently from your Zabbix Docker containers:
- Zabbix uses ports 80/443/10051
- V2 SOC Dashboard uses port 8444
- Each has its own `docker-compose.yml` in separate directories
- `network_mode: host` gives the container direct access to Wazuh API/Indexer on localhost

---

## Option B: Systemd Deploy (Native, without Docker)

### 1. Copy files to server
```bash
sudo mkdir -p /opt/wazuh-soc-dashboard/{templates,static/css,static/js,certs}
sudo cp app.py /opt/wazuh-soc-dashboard/
sudo cp requirements.txt /opt/wazuh-soc-dashboard/
sudo cp templates/*.html /opt/wazuh-soc-dashboard/templates/
sudo cp static/css/style.css /opt/wazuh-soc-dashboard/static/css/
sudo cp static/js/app.js /opt/wazuh-soc-dashboard/static/js/
```

### 2. Install dependencies (use existing V1 venv)
```bash
/var/ossec/wodles/snmp-icmp-monitor/venv/bin/pip install flask pyyaml werkzeug
```

### 3. Open port 8444
```bash
sudo ufw allow 8444/tcp
```
Also add Azure NSG rule: Destination port 8444, TCP, Allow.

### 4. Test manually first
```bash
sudo /var/ossec/wodles/snmp-icmp-monitor/venv/bin/python /opt/wazuh-soc-dashboard/app.py --port 8444
```
Open: `https://<SERVER_IP>:8444`

### 5. Set up systemd service
```bash
sudo cp soc-dashboard.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now soc-dashboard
sudo systemctl status soc-dashboard
```

---

## Configuration

### Credentials (Docker)
Edit `docker-compose.yml` environment variables to change Wazuh API/Indexer credentials.

### Credentials (Systemd)
Edit `app.py` lines 51-58 or set environment variables:
`WAZUH_API_URL`, `WAZUH_API_USER`, `WAZUH_API_PASS`,
`WAZUH_INDEXER_URL`, `WAZUH_INDEXER_USER`, `WAZUH_INDEXER_PASSWORD`.

## SSL Certificate
The app auto-detects Let's Encrypt certificates. If found, uses them (trusted).
Otherwise generates a self-signed certificate in the `certs/` directory.

## Troubleshooting

### Docker
```bash
# Container status
docker compose ps

# Container logs
docker compose logs --tail=50 soc-dashboard

# Shell into the container
docker exec -it wazuh-soc-dashboard bash

# Check health
docker inspect --format='{{.State.Health.Status}}' wazuh-soc-dashboard

# Rebuild from scratch
docker compose down && docker compose up -d --build --force-recreate
```

### Systemd
```bash
# Check service status
sudo systemctl status soc-dashboard

# View logs
sudo journalctl -u soc-dashboard --no-pager -n 50

# Check log file
sudo tail -50 /var/ossec/logs/soc_dashboard.log

# Test API manually
curl -sk https://127.0.0.1:8444/login
```
