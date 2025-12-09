# ULS Detection Server - Ubuntu Setup Guide

Complete step-by-step guide for setting up the server infrastructure on Ubuntu VM.

---

## Table of Contents
1. [Initial System Setup](#1-initial-system-setup)
2. [Install Docker & Docker Compose](#2-install-docker--docker-compose)
3. [Setup Docker Containers (TimescaleDB + RabbitMQ)](#3-setup-docker-containers-timescaledb--rabbitmq)
4. [Install Go](#4-install-go)
5. [Setup ULS Detection Server](#5-setup-uls-detection-server)
6. [Create Systemd Service](#6-create-systemd-service)
7. [Firewall Configuration](#7-firewall-configuration)
8. [Verification & Testing](#8-verification--testing)
9. [When to Deploy Server Files](#9-when-to-deploy-server-files)

---

## 1. Initial System Setup

### Update System
```bash
sudo apt update && sudo apt upgrade -y
```

### Install Essential Tools
```bash
sudo apt install -y \
    wget \
    curl \
    git \
    gnupg2 \
    software-properties-common \
    apt-transport-https \
    ca-certificates \
    lsb-release \
    vim \
    net-tools
```

### Set System Timezone (Optional)
```bash
sudo timedatectl set-timezone Asia/Kolkata

# Or your preferred timezone
```

---

## 2. Install Docker & Docker Compose

### Install Docker
```bash
# Install prerequisites
sudo apt install -y ca-certificates curl gnupg lsb-release

# Add Docker's official GPG key
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg

# Add Docker repository
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

# Install Docker Engine
sudo apt update
sudo apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
```

### Configure Docker
```bash
# Start and enable Docker
sudo systemctl start docker
sudo systemctl enable docker

# Add your user to docker group (to run docker without sudo)
sudo usermod -aG docker $USER

# Apply group changes (or logout/login)
newgrp docker

# Verify installation
docker --version
docker compose version
```

### Test Docker
```bash
docker run hello-world
```

---

## 3. Setup Docker Containers (TimescaleDB + RabbitMQ)

### Create Project Directory
```bash
mkdir -p ~/uls-infrastructure
cd ~/uls-infrastructure
```

### Create Docker Compose File
```bash
nano docker-compose.yml
```

Add the following content:

```yaml
version: '3.8'

services:
  timescaledb:
    image: timescale/timescaledb:latest-pg15
    container_name: uls-timescaledb
    restart: unless-stopped
    environment:
      POSTGRES_DB: uls_detection
      POSTGRES_USER: uls_user
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:-your_secure_password_here}
      POSTGRES_INITDB_ARGS: "-E UTF8"
    volumes:
      - timescaledb_data:/var/lib/postgresql/data
      - ./init-scripts:/docker-entrypoint-initdb.d
    ports:
      - "5432:5432"
    networks:
      - uls-network
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U uls_user -d uls_detection"]
      interval: 10s
      timeout: 5s
      retries: 5

  rabbitmq:
    image: rabbitmq:3.12-management-alpine
    container_name: uls-rabbitmq
    restart: unless-stopped
    environment:
      RABBITMQ_DEFAULT_USER: ${RABBITMQ_USER:-uls_admin}
      RABBITMQ_DEFAULT_PASS: ${RABBITMQ_PASSWORD:-your_rabbitmq_password}
      RABBITMQ_DEFAULT_VHOST: /
    volumes:
      - rabbitmq_data:/var/lib/rabbitmq
      - ./rabbitmq.conf:/etc/rabbitmq/rabbitmq.conf:ro
    ports:
      - "5672:5672"   # AMQP port
      - "15672:15672" # Management UI
    networks:
      - uls-network
    healthcheck:
      test: ["CMD", "rabbitmq-diagnostics", "ping"]
      interval: 10s
      timeout: 5s
      retries: 5

volumes:
  timescaledb_data:
    driver: local
  rabbitmq_data:
    driver: local

networks:
  uls-network:
    driver: bridge
```

### Create Environment File
```bash
nano .env
```

Add the following:
```bash
# PostgreSQL/TimescaleDB
POSTGRES_PASSWORD=YourSecurePassword123!

# RabbitMQ
RABBITMQ_USER=uls_admin
RABBITMQ_PASSWORD=YourRabbitMQPassword123!
```

### Create RabbitMQ Configuration
```bash
nano rabbitmq.conf
```

Add the following:
```conf
# Network and protocol configuration
listeners.tcp.default = 5672
management.tcp.port = 15672

# Memory and disk limits
vm_memory_high_watermark.relative = 0.6
disk_free_limit.absolute = 2GB

# Logging
log.file.level = info
log.console = true
log.console.level = info

# Queue settings
queue_master_locator = min-masters
```

### Create TimescaleDB Initialization Script (Optional)
```bash
mkdir -p init-scripts
nano init-scripts/01-init-timescaledb.sql
```

Add the following:
```sql
-- Enable TimescaleDB extension
CREATE EXTENSION IF NOT EXISTS timescaledb;

-- Grant privileges
GRANT ALL PRIVILEGES ON DATABASE uls_detection TO uls_user;
GRANT ALL ON SCHEMA public TO uls_user;
```

### Start the Containers
```bash
cd ~/uls-infrastructure

# Start all services
docker compose up -d

# Check status
docker compose ps

# View logs
docker compose logs -f
```

### Verify Containers are Running
```bash
# Check TimescaleDB
docker exec -it uls-timescaledb psql -U uls_user -d uls_detection -c "SELECT extversion FROM pg_extension WHERE extname='timescaledb';"

# Check RabbitMQ
docker exec -it uls-rabbitmq rabbitmqctl status
```

### Access Services
- **TimescaleDB**: `localhost:5432`
- **RabbitMQ AMQP**: `localhost:5672`
- **RabbitMQ Management UI**: `http://your-server-ip:15672`

### Useful Docker Commands
```bash
# Stop all containers
docker compose down

# Stop and remove volumes (WARNING: Deletes all data!)
docker compose down -v

# Restart services
docker compose restart

# View logs for specific service
docker compose logs -f timescaledb
docker compose logs -f rabbitmq

# Execute commands in containers
docker exec -it uls-timescaledb psql -U uls_user -d uls_detection
docker exec -it uls-rabbitmq rabbitmqctl list_queues
```

---

## 4. Install Go

### Download and Install Go 1.21+
```bash
# Download Go (check for latest version at https://go.dev/dl/)
wget https://go.dev/dl/go1.21.5.linux-amd64.tar.gz

# Remove old Go installation (if exists)
sudo rm -rf /usr/local/go

# Extract Go
sudo tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz

# Clean up
rm go1.21.5.linux-amd64.tar.gz
```

### Configure Go Environment
```bash
# Add Go to PATH in .bashrc
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
echo 'export GOPATH=$HOME/go' >> ~/.bashrc
echo 'export PATH=$PATH:$GOPATH/bin' >> ~/.bashrc

# Reload bashrc
source ~/.bashrc
```

### Verify Go Installation
```bash
go version
```

---

## 5. Setup ULS Detection Server

### Create Application Directory
```bash
sudo mkdir -p /opt/uls-detection-server
sudo chown $USER:$USER /opt/uls-detection-server
```

### Clone or Copy Your Application
```bash
cd /opt/uls-detection-server

# If using git
git clone <your-repo-url> .

# Or copy files from your development machine
# scp -r /path/to/uls-detection-server user@server-ip:/opt/uls-detection-server/
```

### Set Environment Variables
```bash
# Create environment file for the server
nano /opt/uls-detection-server/.env
```

Add the following (use passwords from ~/uls-infrastructure/.env):
```bash
# RabbitMQ Configuration
RABBITMQ_HOST=localhost
RABBITMQ_PORT=5672
RABBITMQ_USER=uls_admin
RABBITMQ_PASS=YourRabbitMQPassword123!
RABBITMQ_RAW_QUEUE=security_events_raw
RABBITMQ_ENRICHED_QUEUE=security_events_enriched

# PostgreSQL/TimescaleDB Configuration
POSTGRES_HOST=localhost
POSTGRES_PORT=5432
POSTGRES_USER=uls_user
POSTGRES_PASS=YourSecurePassword123!
POSTGRES_DB=uls_detection
POSTGRES_MAX_CONNS=20
POSTGRES_MIN_CONNS=5

# Enrichment Service Configuration
ENRICHMENT_WORKERS=8
ENRICHMENT_PREFETCH=100
ENRICHMENT_PUBLISH_BATCH=50

# DB Writer Service Configuration
DBWRITER_WORKERS=4
DBWRITER_BATCH_SIZE=500
DBWRITER_FLUSH_MS=500
DBWRITER_PREFETCH=200
DBWRITER_MAX_RETRIES=3

# Server Configuration
MODE=combined
HEALTH_PORT=8080
```

### Build the Application
```bash
cd /opt/uls-detection-server
go mod download
go mod tidy
go build -o uls-server ./cmd/server
```

### Test Database Connection
```bash
# Test connection to TimescaleDB container
docker exec -it uls-timescaledb psql -U uls_user -d uls_detection -c "SELECT version();"

# The server will automatically initialize schema on first run
```

### Test the Application (Dry Run)
```bash
# Load environment variables
export $(cat .env | xargs)

# Run the server
./uls-server
```

Press `Ctrl+C` to stop after verifying it starts without errors and connects to both RabbitMQ and TimescaleDB.

---

## 6. Create Systemd Service

### Create Service File
```bash
sudo vim /etc/systemd/system/uls-detection-server.service
```

Add the following:
```ini
[Unit]
Description=ULS Detection Server
After=network.target docker.service
Requires=docker.service

[Service]
Type=simple
User=uls-service
Group=uls-service
WorkingDirectory=/opt/uls-detection-server
EnvironmentFile=/opt/uls-detection-server/.env
ExecStart=/opt/uls-detection-server/uls-server
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=uls-detection-server

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/opt/uls-detection-server/logs

[Install]
WantedBy=multi-user.target
```

### Create Service User
```bash
sudo useradd -r -s /bin/false uls-service

# Add uls-service user to docker group (to access Docker containers)
sudo usermod -aG docker uls-service

# Set ownership
sudo chown -R uls-service:uls-service /opt/uls-detection-server
```

### Create Log Directory
```bash
sudo mkdir -p /opt/uls-detection-server/logs
sudo chown uls-service:uls-service /opt/uls-detection-server/logs
```

### Enable and Start Service
```bash
# Reload systemd
sudo systemctl daemon-reload

# Enable service to start on boot
sudo systemctl enable uls-detection-server

# Start the service
sudo systemctl start uls-detection-server

# Check status
sudo systemctl status uls-detection-server
```

### View Logs
```bash
# View real-time logs
sudo journalctl -u uls-detection-server -f

# View recent logs
sudo journalctl -u uls-detection-server -n 100

# View logs from today
sudo journalctl -u uls-detection-server --since today
```

---

## 7. Firewall Configuration

### Install UFW (if not installed)
```bash
sudo apt install -y ufw
```

### Configure Firewall Rules
```bash
# Allow SSH (IMPORTANT: Do this first!)
sudo ufw allow 22/tcp

# Allow PostgreSQL (if remote access needed)
sudo ufw allow 5432/tcp

# Allow RabbitMQ
sudo ufw allow 5672/tcp
sudo ufw allow 15672/tcp

# Allow ULS Server API (if needed)
sudo ufw allow 8080/tcp

# Enable firewall
sudo ufw enable

# Check status
sudo ufw status verbose
```

### Alternative: Using iptables
```bash
# Allow PostgreSQL
sudo iptables -A INPUT -p tcp --dport 5432 -j ACCEPT

# Allow RabbitMQ
sudo iptables -A INPUT -p tcp --dport 5672 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 15672 -j ACCEPT

# Allow ULS Server
sudo iptables -A INPUT -p tcp --dport 8080 -j ACCEPT

# Save rules
sudo netfilter-persistent save
```

---

## 8. Verification & Testing

### Check All Services
```bash
# Docker containers
docker compose -f ~/uls-infrastructure/docker-compose.yml ps

# TimescaleDB
docker exec -it uls-timescaledb psql -U uls_user -d uls_detection -c "SELECT version();"
docker exec -it uls-timescaledb psql -U uls_user -d uls_detection -c "SELECT extversion FROM pg_extension WHERE extname='timescaledb';"

# RabbitMQ
docker exec -it uls-rabbitmq rabbitmqctl status

# ULS Detection Server
sudo systemctl status uls-detection-server
```

### Test Database Connection
```bash
# Connect to TimescaleDB
docker exec -it uls-timescaledb psql -U uls_user -d uls_detection
```

```sql
-- List all tables
\dt

-- Check if hypertables are created
SELECT * FROM timescaledb_information.hypertables;

-- Exit
\q
```

### Test RabbitMQ Connection
```bash
# Check queues
docker exec -it uls-rabbitmq rabbitmqctl list_queues

# Check exchanges
docker exec -it uls-rabbitmq rabbitmqctl list_exchanges

# Access RabbitMQ Management UI
# Open browser: http://your-server-ip:15672
# Login with credentials from .env file
```

### Test ULS Server API (if HTTP endpoint exists)
```bash
curl http://localhost:8080/health
curl http://localhost:8080/metrics
```

### Monitor System Resources
```bash
# Check Docker containers
docker ps
docker stats

# Check memory usage
free -h

# Check disk usage
df -h

# Check Docker volumes
docker volume ls

# Check network connections
sudo netstat -tulpn | grep -E '5432|5672|15672|8080'
```

---

---

## 9. When to Deploy Server Files

### Deployment Timing

**Deploy your server-side Go files AFTER completing these steps:**

1. ✅ Docker and Docker Compose installed (Step 2)
2. ✅ TimescaleDB and RabbitMQ containers running (Step 3)
3. ✅ Go installed on the server (Step 4)
4. ✅ Verified both containers are healthy and accessible

### Deployment Checklist

Before copying files to `/opt/uls-detection-server`:

- [ ] Docker containers are running: `docker ps`
- [ ] Can connect to TimescaleDB: `docker exec -it uls-timescaledb psql -U uls_user -d uls_detection`
- [ ] RabbitMQ Management UI accessible: `http://your-server-ip:15672`
- [ ] Go is installed: `go version`
- [ ] Directory `/opt/uls-detection-server` created with proper permissions

### How to Deploy Files

**Option 1: Using Git (Recommended)**
```bash
cd /opt/uls-detection-server
git clone https://github.com/your-org/uls-detection-server.git .
```

**Option 2: Using SCP from Windows**
```powershell
# From your Windows machine (PowerShell)
scp -r C:\ProgramData\CustomSecurityLogs\CUSTOM_LOGGERS\server_side\uls-detection-server\* user@your-server-ip:/opt/uls-detection-server/
```

**Option 3: Using rsync**
```bash
# From another Linux machine
rsync -avz --progress /path/to/uls-detection-server/ user@your-server-ip:/opt/uls-detection-server/
```

### After Deployment

1. **Build the application:**
```bash
cd /opt/uls-detection-server
go mod download
go build -o uls-server ./cmd/server
```

2. **Test manually first:**
```bash
export $(cat .env | xargs)
./uls-server
```

3. **If successful, setup systemd service** (Step 6)

4. **Start testing the full pipeline with Windows agents**

---

## Maintenance Commands

### Docker Container Management
```bash
# View container logs
docker compose -f ~/uls-infrastructure/docker-compose.yml logs -f

# Restart containers
docker compose -f ~/uls-infrastructure/docker-compose.yml restart

# Stop containers
docker compose -f ~/uls-infrastructure/docker-compose.yml down

# Start containers
docker compose -f ~/uls-infrastructure/docker-compose.yml up -d
```

### PostgreSQL/TimescaleDB Maintenance
```bash
# Backup database
docker exec uls-timescaledb pg_dump -U uls_user uls_detection > backup_$(date +%Y%m%d).sql

# Restore database
cat backup_20231208.sql | docker exec -i uls-timescaledb psql -U uls_user -d uls_detection

# Vacuum database
docker exec -it uls-timescaledb psql -U uls_user -d uls_detection -c "VACUUM ANALYZE;"

# Access database shell
docker exec -it uls-timescaledb psql -U uls_user -d uls_detection
```

### RabbitMQ Maintenance
```bash
# Check queue depth
docker exec uls-rabbitmq rabbitmqctl list_queues name messages messages_ready messages_unacknowledged

# Purge queue (careful!)
docker exec uls-rabbitmq rabbitmqctl purge_queue security_events_raw

# List users
docker exec uls-rabbitmq rabbitmqctl list_users

# View logs
docker logs -f uls-rabbitmq
```

### ULS Server Maintenance
```bash
# Restart service
sudo systemctl restart uls-detection-server

# Stop service
sudo systemctl stop uls-detection-server

# View configuration
cat /opt/uls-detection-server/config.json

# Update application
cd /opt/uls-detection-server
git pull  # or copy new files
go build -o uls-server ./cmd/server
sudo systemctl restart uls-detection-server
```

---

## Troubleshooting

### Docker Container Issues
```bash
# Check container status
docker ps -a

# View container logs
docker logs uls-timescaledb
docker logs uls-rabbitmq

# Restart specific container
docker restart uls-timescaledb
docker restart uls-rabbitmq

# Check container health
docker inspect uls-timescaledb | grep -A 10 Health
docker inspect uls-rabbitmq | grep -A 10 Health
```

### TimescaleDB Issues
```bash
# Check TimescaleDB logs
docker logs -f uls-timescaledb

# Check if TimescaleDB is accepting connections
docker exec -it uls-timescaledb pg_isready -U uls_user

# Connect to database for debugging
docker exec -it uls-timescaledb psql -U uls_user -d uls_detection
```

### RabbitMQ Issues
```bash
# Check RabbitMQ logs
docker logs -f uls-rabbitmq

# Check RabbitMQ status
docker exec -it uls-rabbitmq rabbitmqctl status

# Check if management plugin is enabled
docker exec -it uls-rabbitmq rabbitmq-plugins list
```

### ULS Server Issues
```bash
# Check service logs
sudo journalctl -u uls-detection-server -n 100

# Check if port is in use
sudo netstat -tulpn | grep 8080

# Run manually for debugging
cd /opt/uls-detection-server
sudo -u uls-service ./uls-server
```

### Network Connectivity
```bash
# Test from client machine
telnet server-ip 5432
telnet server-ip 5672
telnet server-ip 8080

# Check firewall rules
sudo ufw status verbose
sudo iptables -L -n -v
```

---

## Security Hardening (Optional)

### Docker Security
```bash
# Run Docker in rootless mode (advanced)
# See: https://docs.docker.com/engine/security/rootless/

# Limit container resources in docker-compose.yml
# Add under each service:
#   deploy:
#     resources:
#       limits:
#         cpus: '2.0'
#         memory: 2G
```

### TimescaleDB Security
```bash
# Use SSL/TLS connections
# Update docker-compose.yml to mount SSL certificates
# Add to timescaledb environment:
#   POSTGRES_HOST_AUTH_METHOD: scram-sha-256
```

### RabbitMQ Security
```bash
# Enable SSL/TLS in RabbitMQ
# Update rabbitmq.conf with SSL settings
# Mount SSL certificates in docker-compose.yml
```

### System Security
```bash
# Keep system updated
sudo apt update && sudo apt upgrade -y

# Install fail2ban
sudo apt install -y fail2ban

# Configure automatic security updates
sudo apt install -y unattended-upgrades
sudo dpkg-reconfigure -plow unattended-upgrades
```

---

## Performance Tuning

### TimescaleDB Container Tuning
Create `~/uls-infrastructure/postgresql.conf`:
```conf
# Memory Settings (adjust based on your server RAM)
shared_buffers = 1GB
effective_cache_size = 3GB
maintenance_work_mem = 256MB
work_mem = 10MB

# Connection Settings
max_connections = 200

# Performance
random_page_cost = 1.1
effective_io_concurrency = 200

# TimescaleDB specific
timescaledb.max_background_workers = 8
```

Then update docker-compose.yml:
```yaml
timescaledb:
  volumes:
    - ./postgresql.conf:/etc/postgresql/postgresql.conf:ro
  command: postgres -c config_file=/etc/postgresql/postgresql.conf
```

### Docker Performance
```bash
# Allocate more resources to Docker
# Edit /etc/docker/daemon.json
sudo nano /etc/docker/daemon.json
```

Add:
```json
{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  }
}
```

Restart Docker:
```bash
sudo systemctl restart docker
```

---

## Next Steps

1. **Deploy Server Files**: Copy Go server files to `/opt/uls-detection-server` (see Step 9)
2. **Build and Test**: Build the Go application and test with manual run
3. **Enable Systemd Service**: Start the ULS server as a system service
4. **Configure Windows Agents**: Update PowerShell scripts with server IP and credentials
5. **Test Full Pipeline**: Send test events from Windows agents to verify end-to-end flow
6. **Setup Monitoring**: Consider installing Prometheus + Grafana
7. **Configure Backups**: Setup automated Docker volume backups
8. **Implement SSL/TLS**: Secure communications in production

---

## Quick Reference

### Service Management Commands
```bash
# Docker Containers (TimescaleDB + RabbitMQ)
cd ~/uls-infrastructure
docker compose up -d              # Start all containers
docker compose down               # Stop all containers
docker compose restart            # Restart all containers
docker compose ps                 # Check status
docker compose logs -f            # View logs

# ULS Detection Server
sudo systemctl start uls-detection-server
sudo systemctl stop uls-detection-server
sudo systemctl restart uls-detection-server
sudo systemctl status uls-detection-server
```

### Connection Strings
```bash
# PostgreSQL
postgresql://uls_user:password@localhost:5432/uls_detection

# RabbitMQ
amqp://uls_admin:password@localhost:5672/
```

### Default Ports
- PostgreSQL: 5432
- RabbitMQ AMQP: 5672
- RabbitMQ Management: 15672
- ULS Server API: 8080

---

## Support & Documentation

- TimescaleDB Docs: https://docs.timescale.com/
- RabbitMQ Docs: https://www.rabbitmq.com/documentation.html
- PostgreSQL Docs: https://www.postgresql.org/docs/
- Go Documentation: https://go.dev/doc/

---

**Document Version**: 1.0  
**Last Updated**: December 8, 2025  
**Tested On**: Ubuntu 22.04 LTS, Ubuntu 20.04 LTS
