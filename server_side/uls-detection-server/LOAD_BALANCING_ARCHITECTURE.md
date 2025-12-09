# Load Balancing & Concurrency Architecture

## Overview: Gunicorn vs Go Native Concurrency

Your previous Python setup used **Gunicorn** for load balancing. Your new Go implementation uses a **fundamentally different approach** that's actually more efficient and scalable.

---

## Previous Architecture (Python + Gunicorn)

### Gunicorn Multi-Process Model
```
                    ┌─────────────────┐
Client Requests ──> │   Gunicorn      │
                    │   (Load Bal.)   │
                    └────────┬────────┘
                             │
            ┌────────────────┼────────────────┐
            │                │                │
       ┌────▼────┐     ┌────▼────┐     ┌────▼────┐
       │ Worker 1│     │ Worker 2│     │ Worker 3│
       │(Process)│     │(Process)│     │(Process)│
       └─────────┘     └─────────┘     └─────────┘
```

**How it worked:**
- Gunicorn spawned **multiple Python processes** (workers)
- Each worker handled requests independently
- OS kernel distributed incoming connections across workers
- Each worker had its own memory space (inefficient)
- GIL (Global Interpreter Lock) limited Python's true parallelism

**Typical Configuration:**
```bash
gunicorn --workers 4 --threads 2 --bind 0.0.0.0:8000 app:app
```

---

## Current Architecture (Go + Goroutines)

### Go Native Concurrency Model
```
                    ┌─────────────────────────────────────┐
                    │   Single Go Process                  │
                    │                                      │
                    │  ┌──────────────────────────────┐  │
RabbitMQ Raw ──────>│  │  Enrichment Service          │  │
Events              │  │                               │  │
                    │  │  ┌─────────┐  ┌─────────┐   │  │
                    │  │  │Worker 1 │  │Worker 2 │   │  │──> RabbitMQ
                    │  │  │(Gorout.)│  │(Gorout.)│   │  │   Enriched
                    │  │  └─────────┘  └─────────┘   │  │
                    │  │  ┌─────────┐  ┌─────────┐   │  │
                    │  │  │Worker 3 │  │Worker N │   │  │
                    │  │  │(Gorout.)│  │(Gorout.)│   │  │
                    │  │  └─────────┘  └─────────┘   │  │
                    │  └──────────────────────────────┘  │
                    │                                      │
                    │  ┌──────────────────────────────┐  │
RabbitMQ Enriched ──>  │  DB Writer Service           │  │
Events              │  │                               │  │
                    │  │  ┌─────────┐  ┌─────────┐   │  │
                    │  │  │Writer 1 │  │Writer 2 │   │  │──> TimescaleDB
                    │  │  │(Gorout.)│  │(Gorout.)│   │  │   (Batched)
                    │  │  └─────────┘  └─────────┘   │  │
                    │  │  ┌─────────┐  ┌─────────┐   │  │
                    │  │  │Writer 3 │  │Writer N │   │  │
                    │  │  │(Gorout.)│  │(Gorout.)│   │  │
                    │  │  └─────────┘  └─────────┘   │  │
                    │  └──────────────────────────────┘  │
                    └─────────────────────────────────────┘
```

**How it works:**
- **Single process** with lightweight goroutines
- True concurrent execution (no GIL)
- Shared memory space (efficient)
- Worker pool pattern for both enrichment and DB writing
- RabbitMQ provides queue-based load distribution

---

## Detailed Load Balancing Mechanisms

### 1. RabbitMQ Prefetch (Consumer-Level Load Balancing)

**Configuration in your code:**
```go
// Enrichment Service
Prefetch: 100  // Pull up to 100 messages at once

// DB Writer Service  
Prefetch: 200  // Pull up to 200 messages at once
```

**How RabbitMQ distributes load:**
```
RabbitMQ Queue (10,000 messages)
│
├─> Consumer 1 (Prefetch: 100) → Processing 100 messages
├─> Consumer 2 (Prefetch: 100) → Processing 100 messages  
├─> Consumer 3 (Prefetch: 100) → Processing 100 messages
└─> Consumer 4 (Prefetch: 100) → Processing 100 messages

As each consumer ACKs messages, RabbitMQ sends more
```

**Benefits:**
- ✅ Fair distribution across consumers
- ✅ Prevents one worker from being overwhelmed
- ✅ Automatic backpressure mechanism
- ✅ If a worker dies, messages are redistributed

### 2. Worker Pool Pattern (Application-Level Load Balancing)

**Enrichment Service Configuration:**
```go
Enrichment: EnrichmentConfig{
    NumWorkers:   8,   // 8 goroutine workers
    Prefetch:     100, // Pull 100 messages from RabbitMQ
    PublishBatch: 50,  // Publish in batches of 50
}
```

**How the worker pool works:**
```go
// In enrichment/service.go

// Start worker pool
for i := 0; i < s.config.NumWorkers; i++ {
    s.wg.Add(1)
    go s.enrichmentWorker(i)  // Each goroutine is a worker
}

// Workers pull from shared channel
func (s *Service) enrichmentWorker(id int) {
    for {
        select {
        case delivery := <-s.eventChan:
            // Process events
            for i := range delivery.events {
                // Apply detection rules
                result := s.detector.Detect(&delivery.events[i])
                
                // Create enriched event
                enriched := &models.EnrichedEvent{...}
                
                // Send to publisher channel
                s.enrichedChan <- enriched
            }
        }
    }
}
```

**Load Distribution:**
```
                RabbitMQ Consumer
                      │
                      ▼
              ┌──────────────┐
              │  eventChan   │  (Buffered channel)
              └──────┬───────┘
                     │
        ┌────────────┼────────────┐
        │            │            │
   ┌────▼───┐  ┌────▼───┐  ┌────▼───┐
   │Worker 1│  │Worker 2│  │Worker 3│
   └────┬───┘  └────┬───┘  └────┬───┘
        │            │            │
        └────────────┼────────────┘
                     ▼
              ┌──────────────┐
              │enrichedChan  │
              └──────────────┘
```

**Go's runtime automatically balances goroutines** across available CPU cores.

### 3. Batch Processing (Throughput Optimization)

**DB Writer Batching:**
```go
DBWriter: DBWriterConfig{
    NumWorkers:    4,     // 4 goroutine workers
    BatchSize:     500,   // Write 500 events at once
    FlushInterval: 500ms, // Or flush every 500ms
    Prefetch:      200,   // Pull 200 from RabbitMQ
    MaxRetries:    3,     // Retry failed batches
}
```

**Batching Algorithm:**
```go
func (s *Service) batchCollector() {
    batch := eventBatch{
        events: make([]models.SecurityEvent, 0, s.config.BatchSize),
        msgs:   make([]amqp.Delivery, 0, s.config.BatchSize),
    }
    
    ticker := time.NewTicker(s.config.FlushInterval)
    defer ticker.Stop()
    
    for {
        select {
        case msg := <-msgs:
            // Add to batch
            batch.events = append(batch.events, events...)
            batch.msgs = append(batch.msgs, msg)
            
            // Flush if batch is full
            if len(batch.events) >= s.config.BatchSize {
                s.eventChan <- batch
                batch = newBatch()
            }
            
        case <-ticker.C:
            // Flush on timer (prevents stale data)
            if len(batch.events) > 0 {
                s.eventChan <- batch
                batch = newBatch()
            }
        }
    }
}
```

**Performance Impact:**
- Single insert: ~5-10ms per event = 100-200 events/sec
- Batch insert (500): ~50ms for 500 events = **10,000 events/sec**

---

## Scaling Strategies

### Vertical Scaling (Single Server)

**Adjust worker counts based on CPU cores:**

```bash
# For 8-core server
export ENRICHMENT_WORKERS=16    # 2x cores (CPU-bound)
export DBWRITER_WORKERS=8       # 1x cores (I/O-bound)

# For 16-core server
export ENRICHMENT_WORKERS=32
export DBWRITER_WORKERS=16
```

**Rule of thumb:**
- **CPU-bound tasks** (enrichment/detection): 1.5-2x CPU cores
- **I/O-bound tasks** (DB writes): 1-1.5x CPU cores
- **Network I/O** (RabbitMQ): Adjust prefetch based on latency

### Horizontal Scaling (Multiple Servers)

**Option 1: Separate Services (Microservices)**

```bash
# Server 1: Enrichment Only
export MODE=enrichment
export ENRICHMENT_WORKERS=32
./uls-server

# Server 2: DB Writer Only  
export MODE=dbwriter
export DBWRITER_WORKERS=16
./uls-server

# Server 3: Another Enrichment
export MODE=enrichment
export ENRICHMENT_WORKERS=32
./uls-server
```

**Architecture:**
```
                    ┌─────────────┐
                    │  RabbitMQ   │
                    │  Raw Queue  │
                    └──────┬──────┘
                           │
          ┌────────────────┼────────────────┐
          │                │                │
    ┌─────▼─────┐    ┌─────▼─────┐    ┌─────▼─────┐
    │ Enrichment│    │ Enrichment│    │ Enrichment│
    │ Server 1  │    │ Server 2  │    │ Server 3  │
    └─────┬─────┘    └─────┬─────┘    └─────┬─────┘
          │                │                │
          └────────────────┼────────────────┘
                           │
                    ┌──────▼──────┐
                    │  RabbitMQ   │
                    │Enriched Q   │
                    └──────┬──────┘
                           │
          ┌────────────────┼────────────────┐
          │                │                │
    ┌─────▼─────┐    ┌─────▼─────┐    ┌─────▼─────┐
    │ DB Writer │    │ DB Writer │    │ DB Writer │
    │ Server 1  │    │ Server 2  │    │ Server 3  │
    └─────┬─────┘    └─────┬─────┘    └─────┬─────┘
          │                │                │
          └────────────────┼────────────────┘
                           │
                    ┌──────▼──────┐
                    │ TimescaleDB │
                    └─────────────┘
```

**Benefits:**
- ✅ Each service can scale independently
- ✅ RabbitMQ automatically load balances across consumers
- ✅ No single point of failure (except RabbitMQ/DB)

**Option 2: Combined Mode with Multiple Instances**

```bash
# Run 3 identical servers
# Server 1
export MODE=combined
./uls-server

# Server 2
export MODE=combined
./uls-server

# Server 3
export MODE=combined
./uls-server
```

RabbitMQ will distribute messages across all consumers automatically.

---

## RabbitMQ Queue Configuration for Load Balancing

### Classic Queue vs Quorum Queue

**Your current config (Classic Queue):**
```go
amqp.Table{
    "x-queue-type": "classic",
}
```

**For high-availability, use Quorum Queue:**
```go
amqp.Table{
    "x-queue-type": "quorum",
    "x-max-length": 100000,  // Cap queue size
    "x-overflow": "reject-publish",  // Reject if full
}
```

### Dead Letter Queue (DLQ) Pattern

**Handle failed messages:**
```go
// Main queue with DLQ
_, err = ch.QueueDeclare(
    "security_events_raw",
    true,
    false,
    false,
    false,
    amqp.Table{
        "x-queue-type": "quorum",
        "x-dead-letter-exchange": "dlx",
        "x-dead-letter-routing-key": "security_events_failed",
        "x-message-ttl": 3600000,  // 1 hour TTL
    },
)

// Dead letter queue
_, err = ch.QueueDeclare(
    "security_events_failed",
    true,
    false,
    false,
    false,
    amqp.Table{
        "x-queue-type": "quorum",
    },
)
```

---

## Comparison Table: Gunicorn vs Go Native

| Feature | Gunicorn (Python) | Go Native |
|---------|-------------------|-----------|
| **Concurrency Model** | Multi-process (fork) | Goroutines (green threads) |
| **Memory Overhead** | ~50-100MB per worker | ~2KB per goroutine |
| **Context Switching** | OS-level (expensive) | Go runtime (cheap) |
| **True Parallelism** | Limited by GIL | Full multi-core |
| **Load Balancer** | External (Gunicorn) | Internal (Go runtime + RabbitMQ) |
| **Typical Workers** | 4-8 processes | 100-1000s goroutines |
| **Shared Memory** | No (requires IPC/Redis) | Yes (built-in) |
| **Startup Time** | Slow (~1-2s per worker) | Fast (~100ms total) |
| **Graceful Shutdown** | Complex | Built-in |
| **Resource Usage** | High (multiple processes) | Low (single process) |
| **Throughput** | ~1,000-5,000 req/s | ~50,000-100,000 req/s |

---

## Performance Benchmarks

### Expected Throughput (Single 8-core Server)

**Enrichment Service:**
- 8 workers × 1,000 events/sec = **8,000 events/sec**
- With optimization: **15,000-20,000 events/sec**

**DB Writer Service:**  
- 4 workers × 500 batch size × 2 batches/sec = **4,000 events/sec**
- With larger batches (1000): **8,000-10,000 events/sec**

**Bottlenecks to watch:**
1. **Database I/O** - Most likely bottleneck
2. **RabbitMQ throughput** - Can handle 50K+ msg/sec
3. **Network bandwidth** - Usually not an issue on LAN

---

## Monitoring & Auto-Scaling

### Built-in Metrics (Health Endpoint)

Your server exposes metrics:
```bash
curl http://localhost:8080/health
```

**Response:**
```json
{
  "enrichment": {
    "events_received": 15000,
    "events_enriched": 14950,
    "errors": 50,
    "avg_enrich_time_us": 250
  },
  "dbwriter": {
    "events_received": 14950,
    "events_inserted": 14900,
    "batches_written": 30,
    "errors": 5,
    "avg_batch_time_ms": 45
  },
  "rabbitmq": {
    "raw_queue_depth": 1200,
    "enriched_queue_depth": 350
  }
}
```

### Dynamic Worker Adjustment (Future Enhancement)

**Pseudo-code for auto-scaling:**
```go
func (s *Service) AutoScale() {
    ticker := time.NewTicker(1 * time.Minute)
    for {
        select {
        case <-ticker.C:
            queueDepth := s.getQueueDepth()
            currentWorkers := s.config.NumWorkers
            
            if queueDepth > 10000 && currentWorkers < 32 {
                // Scale up
                s.addWorkers(4)
            } else if queueDepth < 100 && currentWorkers > 4 {
                // Scale down
                s.removeWorkers(2)
            }
        }
    }
}
```

---

## Recommended Configuration

### Small Deployment (1-10 agents)
```bash
# Single server, combined mode
export MODE=combined
export ENRICHMENT_WORKERS=4
export DBWRITER_WORKERS=2
export DBWRITER_BATCH_SIZE=200
export ENRICHMENT_PREFETCH=50
export DBWRITER_PREFETCH=100
```

### Medium Deployment (10-100 agents)
```bash
# Single powerful server, combined mode
export MODE=combined
export ENRICHMENT_WORKERS=16
export DBWRITER_WORKERS=8
export DBWRITER_BATCH_SIZE=500
export ENRICHMENT_PREFETCH=200
export DBWRITER_PREFETCH=400
```

### Large Deployment (100-1000 agents)
```bash
# Multiple servers, separate services

# Enrichment Servers (3x)
export MODE=enrichment
export ENRICHMENT_WORKERS=32
export ENRICHMENT_PREFETCH=500

# DB Writer Servers (2x)
export MODE=dbwriter
export DBWRITER_WORKERS=16
export DBWRITER_BATCH_SIZE=1000
export DBWRITER_PREFETCH=800
```

---

## Key Advantages Over Gunicorn

### 1. **Better Resource Utilization**
- Gunicorn: 4 workers × 100MB = 400MB
- Go: 1 process with 16 workers = 100MB

### 2. **True Concurrency**
- Python GIL limits parallelism
- Go can fully utilize all CPU cores

### 3. **Built-in Load Balancing**
- No need for external load balancer
- Go runtime handles goroutine scheduling
- RabbitMQ handles consumer distribution

### 4. **Lower Latency**
- Goroutine context switch: ~1-2µs
- Process context switch: ~1-10ms

### 5. **Easier Horizontal Scaling**
- Just run more instances
- RabbitMQ automatically balances
- No nginx/HAProxy needed

### 6. **Better Error Handling**
- Worker crash doesn't affect other workers
- Automatic reconnection to RabbitMQ
- Graceful shutdown built-in

---

## Summary

**Instead of Gunicorn:**
- ✅ Go runtime handles concurrency (goroutines)
- ✅ Worker pool pattern for parallelism
- ✅ RabbitMQ provides queue-based load distribution
- ✅ Channel-based communication (lock-free)
- ✅ Single process = less memory, faster startup

**Load balancing happens at 3 levels:**
1. **RabbitMQ** - Distributes messages across consumers
2. **Worker Pool** - Go channels distribute work across goroutines
3. **Go Runtime** - Schedules goroutines across CPU cores

**Result:** Better performance with less complexity! 🚀

---

**Next Steps:**
1. Deploy and monitor with default settings
2. Adjust worker counts based on CPU usage
3. Monitor queue depths to identify bottlenecks
4. Scale horizontally if single server maxes out
