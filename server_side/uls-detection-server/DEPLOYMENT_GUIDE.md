# ULS Detection Server - Deployment Guide

## Quick Reference: When to Deploy

### Phase 1: Infrastructure Setup (Do First on Server)
✅ Complete Steps 1-4 of SERVER_SETUP_GUIDE.md:
- Install Docker & Docker Compose
- Start TimescaleDB and RabbitMQ containers
- Install Go
- Verify all services are running

### Phase 2: Deploy Server Files (After Infrastructure is Ready)
✅ Copy your Go server code to the Ubuntu server
✅ Build and test the application
✅ Setup systemd service

### Phase 3: Test Pipeline (Final Step)
✅ Configure Windows agents with server IP
✅ Send test events
✅ Verify data flow: Agent → RabbitMQ → Enrichment → DB

---

## Detailed Deployment Steps

### Step 1: Verify Infrastructure is Ready

On your Ubuntu server, run:

```bash
# Check Docker is installed
docker --version

# Check containers are running
docker ps

# Should see:
# - uls-timescaledb (port 5432)
# - uls-rabbitmq (ports 5672, 15672)

# Test TimescaleDB connection
docker exec -it uls-timescaledb psql -U uls_user -d uls_detection -c "SELECT version();"

# Test RabbitMQ
docker exec -it uls-rabbitmq rabbitmqctl status

# Check Go installation
go version
```

**If all above commands work, you're ready for Step 2!**

---

### Step 2: Deploy Server Files

#### Option A: Using Git (Recommended)

```bash
# Create directory
sudo mkdir -p /opt/uls-detection-server
sudo chown $USER:$USER /opt/uls-detection-server

# Clone repository
cd /opt/uls-detection-server
git clone https://github.com/your-org/uls-detection-server.git .
```

#### Option B: Using SCP from Windows

On your **Windows machine** (PowerShell):

```powershell
# Navigate to your server files
cd C:\ProgramData\CustomSecurityLogs\CUSTOM_LOGGERS\server_side\uls-detection-server

# Copy to Ubuntu server
scp -r * your-username@your-server-ip:/opt/uls-detection-server/

# Note: Replace 'your-username' and 'your-server-ip' with actual values
```

#### Option C: Using WinSCP or FileZilla

1. Install WinSCP: https://winscp.net/
2. Connect to your Ubuntu server
3. Navigate to `/opt/uls-detection-server/`
4. Upload all files from `C:\ProgramData\CustomSecurityLogs\CUSTOM_LOGGERS\server_side\uls-detection-server\`

---

### Step 3: Configure Environment

On Ubuntu server:

```bash
cd /opt/uls-detection-server

# Create environment file
nano .env
```

Add the following (use the same passwords from `~/uls-infrastructure/.env`):

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

Save and exit (Ctrl+X, Y, Enter)

---

### Step 4: Build the Application

```bash
cd /opt/uls-detection-server

# Download dependencies
go mod download

# Tidy up
go mod tidy

# Build the server
go build -o uls-server ./cmd/server

# Verify binary was created
ls -lh uls-server
```

---

### Step 5: Test Manually (Before Systemd)

```bash
cd /opt/uls-detection-server

# Load environment variables
export $(cat .env | xargs)

# Run the server
./uls-server
```

**Expected output:**
```
╔════════════════════════════════════════════════════════════╗
║          ULS Detection Server - Double Queue Pipeline      ║
╚════════════════════════════════════════════════════════════╝
Starting in COMBINED mode (Enrichment + DB Writer)
Connected to PostgreSQL: localhost:5432/uls_detection
Initializing database schema...
Schema initialized successfully
Starting enrichment service with 8 workers
Starting DB writer service with 4 workers
╔════════════════════════════════════════════════════════════╗
║  Pipeline running:                                          ║
║  Raw Queue:      security_events_raw                        ║
║  Enriched Queue: security_events_enriched                   ║
║  Enrichment Workers: 8     |  DB Writers: 4                ║
╚════════════════════════════════════════════════════════════╝
```

**If you see errors:**
- Check Docker containers are running: `docker ps`
- Check environment variables: `cat .env`
- Check logs: `docker logs uls-timescaledb` and `docker logs uls-rabbitmq`

**If successful**, press Ctrl+C to stop and proceed to Step 6.

---

### Step 6: Setup Systemd Service

```bash
# Create service file
sudo nano /etc/systemd/system/uls-detection-server.service
```

Add:
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

Create service user:
```bash
# Create service user
sudo useradd -r -s /bin/false uls-service

# Add to docker group
sudo usermod -aG docker uls-service

# Create logs directory
sudo mkdir -p /opt/uls-detection-server/logs

# Set permissions
sudo chown -R uls-service:uls-service /opt/uls-detection-server
```

Enable and start service:
```bash
# Reload systemd
sudo systemctl daemon-reload

# Enable service (start on boot)
sudo systemctl enable uls-detection-server

# Start service
sudo systemctl start uls-detection-server

# Check status
sudo systemctl status uls-detection-server
```

View logs:
```bash
# Real-time logs
sudo journalctl -u uls-detection-server -f

# Last 100 lines
sudo journalctl -u uls-detection-server -n 100
```

---

### Step 7: Verify Database Schema

```bash
# Connect to TimescaleDB
docker exec -it uls-timescaledb psql -U uls_user -d uls_detection
```

Run these commands:
```sql
-- List tables
\dt

-- You should see:
-- security_events
-- detections

-- Check hypertables
SELECT * FROM timescaledb_information.hypertables;

-- You should see both tables as hypertables

-- Exit
\q
```

---

### Step 8: Check RabbitMQ Queues

```bash
# List queues
docker exec -it uls-rabbitmq rabbitmqctl list_queues

# You should see:
# security_events_raw
# security_events_enriched
```

Or access Management UI:
- Open browser: `http://your-server-ip:15672`
- Login: `uls_admin` / `YourRabbitMQPassword123!`
- Go to "Queues" tab - you should see both queues

---

### Step 9: Configure Windows Agents

Now that the server is running, update your Windows PowerShell scripts.

Find and update these files on your Windows machines:
- `SIEM-Sender.ps1`
- `Start-SIEMPipeline.ps1`
- Any other scripts that send to RabbitMQ

**Update the configuration section:**

```powershell
# Old (local):
$RabbitMQHost = "localhost"

# New (your Ubuntu server):
$RabbitMQHost = "192.168.1.100"  # Replace with your actual server IP
$RabbitMQPort = 5672
$RabbitMQUser = "uls_admin"
$RabbitMQPassword = "YourRabbitMQPassword123!"  # Same as server
$RabbitMQQueue = "security_events_raw"  # Important: use 'raw' queue
```

---

### Step 10: Test End-to-End Pipeline

#### On Windows Agent:

```powershell
# Run your logging script
.\ULS_continuous.ps1

# Or test with a simple script
.\Test-UnifiedIntegration.ps1
```

#### On Ubuntu Server:

```bash
# Watch server logs
sudo journalctl -u uls-detection-server -f

# Watch RabbitMQ queues
watch -n 1 'docker exec uls-rabbitmq rabbitmqctl list_queues'

# Check database for incoming events
docker exec -it uls-timescaledb psql -U uls_user -d uls_detection -c \
  "SELECT COUNT(*) FROM security_events WHERE time > NOW() - INTERVAL '5 minutes';"
```

**Success Indicators:**
1. ✅ Messages appear in `security_events_raw` queue
2. ✅ Messages get processed and removed from raw queue
3. ✅ Messages appear briefly in `security_events_enriched` queue
4. ✅ Events appear in TimescaleDB `security_events` table
5. ✅ Detections appear in `detections` table

---

## Troubleshooting

### Issue: "Connection refused to RabbitMQ"

**From Windows Agent:**
```powershell
# Test connection
Test-NetConnection -ComputerName your-server-ip -Port 5672
```

**On Ubuntu Server:**
```bash
# Check firewall
sudo ufw status

# Open port if needed
sudo ufw allow 5672/tcp

# Check RabbitMQ is listening
sudo netstat -tulpn | grep 5672
```

### Issue: "Cannot connect to database"

```bash
# Check TimescaleDB container
docker ps | grep timescale

# Check logs
docker logs uls-timescaledb

# Test connection
docker exec -it uls-timescaledb pg_isready -U uls_user
```

### Issue: "Server crashes on startup"

```bash
# Check server logs
sudo journalctl -u uls-detection-server -n 200

# Common issues:
# - Wrong credentials in .env
# - Docker containers not running
# - Port conflicts
```

### Issue: "Events not appearing in database"

```bash
# Check queue depths
docker exec uls-rabbitmq rabbitmqctl list_queues

# If messages stuck in raw queue:
# - Check enrichment service logs
# - Verify detector is running

# If messages stuck in enriched queue:
# - Check DB writer logs
# - Verify database connection
```

---

## Performance Monitoring

### Check System Resources

```bash
# Container resource usage
docker stats

# Server resource usage
htop

# Disk usage
df -h
docker system df
```

### Check Queue Metrics

```bash
# Queue depths
docker exec uls-rabbitmq rabbitmqctl list_queues name messages messages_ready messages_unacknowledged

# Connection count
docker exec uls-rabbitmq rabbitmqctl list_connections
```

### Check Database Metrics

```sql
-- Connect to database
docker exec -it uls-timescaledb psql -U uls_user -d uls_detection

-- Event count
SELECT COUNT(*) FROM security_events;

-- Events per hour (last 24h)
SELECT 
  time_bucket('1 hour', time) as hour,
  COUNT(*) as event_count
FROM security_events
WHERE time > NOW() - INTERVAL '24 hours'
GROUP BY hour
ORDER BY hour DESC;

-- Chunk information
SELECT * FROM timescaledb_information.chunks;
```

---

## Maintenance

### Daily Tasks

```bash
# Check service status
sudo systemctl status uls-detection-server

# Check logs for errors
sudo journalctl -u uls-detection-server --since today | grep -i error

# Monitor queue depths
docker exec uls-rabbitmq rabbitmqctl list_queues
```

### Weekly Tasks

```bash
# Backup database
docker exec uls-timescaledb pg_dump -U uls_user uls_detection > \
  backup_$(date +%Y%m%d).sql

# Check disk space
df -h
docker system df

# Clean old logs (optional)
sudo journalctl --vacuum-time=7d
```

### Monthly Tasks

```bash
# Update Docker images
cd ~/uls-infrastructure
docker compose pull
docker compose up -d

# Update Go server (if changes)
cd /opt/uls-detection-server
git pull
go build -o uls-server ./cmd/server
sudo systemctl restart uls-detection-server
```

---

## Success Checklist

Before considering deployment complete, verify:

- [ ] Docker containers (TimescaleDB + RabbitMQ) are running
- [ ] ULS server systemd service is active and running
- [ ] Both RabbitMQ queues are created (raw + enriched)
- [ ] TimescaleDB has hypertables (security_events + detections)
- [ ] Windows agent can connect to RabbitMQ (port 5672)
- [ ] Events flow from Windows → RabbitMQ → Database
- [ ] MITRE detections are being generated
- [ ] Firewall rules allow necessary ports (5432, 5672, 15672)
- [ ] Environment files have secure passwords
- [ ] Server logs show no errors
- [ ] Database is accumulating events

---

## Quick Commands Reference

```bash
# Start infrastructure
cd ~/uls-infrastructure && docker compose up -d

# Check services
docker ps
sudo systemctl status uls-detection-server

# View logs
sudo journalctl -u uls-detection-server -f
docker logs -f uls-timescaledb
docker logs -f uls-rabbitmq

# Connect to database
docker exec -it uls-timescaledb psql -U uls_user -d uls_detection

# Check queues
docker exec uls-rabbitmq rabbitmqctl list_queues

# Restart server
sudo systemctl restart uls-detection-server

# Backup database
docker exec uls-timescaledb pg_dump -U uls_user uls_detection > backup.sql
```

---

**Deployment Complete!** 🚀

Your ULS Detection Server is now ready for production use.
