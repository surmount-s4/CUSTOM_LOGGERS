package dbwriter

import (
	"context"
	"encoding/json"
	"log"
	"sync"
	"sync/atomic"
	"time"

	amqp "github.com/rabbitmq/amqp091-go"

	"uls-detection-server/internal/database"
	"uls-detection-server/internal/models"
	"uls-detection-server/internal/queue"
)

// ServiceConfig holds DB writer configuration
type ServiceConfig struct {
	NumWorkers    int
	SourceQueue   string
	BatchSize     int
	FlushInterval time.Duration
	Prefetch      int
	MaxRetries    int
}

// Service handles writing enriched events to database
type Service struct {
	config   ServiceConfig
	consumer *queue.Consumer
	db       *database.DB
	
	// Channels
	eventChan  chan eventBatch
	
	// Control
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
	
	// Metrics
	stats *ServiceStats
}

type eventBatch struct {
	events []models.SecurityEvent
	msgs   []amqp.Delivery
}

// ServiceStats tracks DB writer metrics
type ServiceStats struct {
	EventsReceived uint64
	EventsInserted uint64
	BatchesWritten uint64
	Errors         uint64
	RetryCount     uint64
	AvgBatchTimeMs int64
}

// NewService creates a new DB writer service
func NewService(
	consumer *queue.Consumer,
	db *database.DB,
	config ServiceConfig,
) *Service {
	ctx, cancel := context.WithCancel(context.Background())
	
	// Set defaults
	if config.BatchSize == 0 {
		config.BatchSize = 500
	}
	if config.FlushInterval == 0 {
		config.FlushInterval = 500 * time.Millisecond
	}
	if config.MaxRetries == 0 {
		config.MaxRetries = 3
	}
	if config.NumWorkers == 0 {
		config.NumWorkers = 4
	}
	
	return &Service{
		config:    config,
		consumer:  consumer,
		db:        db,
		eventChan: make(chan eventBatch, config.NumWorkers*2),
		ctx:       ctx,
		cancel:    cancel,
		stats:     &ServiceStats{},
	}
}

// Start begins the DB writer pipeline
func (s *Service) Start() error {
	log.Printf("Starting DB writer service with %d workers, batch size %d",
		s.config.NumWorkers, s.config.BatchSize)
	
	// Start batcher (collects events into batches)
	s.wg.Add(1)
	go s.batcher()
	
	// Start writer workers
	for i := 0; i < s.config.NumWorkers; i++ {
		s.wg.Add(1)
		go s.writerWorker(i)
	}
	
	// Start stats reporter
	go s.reportStats()
	
	return nil
}

// batcher collects events into batches before sending to writers
func (s *Service) batcher() {
	defer s.wg.Done()
	
	msgs, err := s.consumer.Consume()
	if err != nil {
		log.Printf("Failed to start consuming: %v", err)
		return
	}
	
	batch := eventBatch{
		events: make([]models.SecurityEvent, 0, s.config.BatchSize),
		msgs:   make([]amqp.Delivery, 0, s.config.BatchSize),
	}
	
	ticker := time.NewTicker(s.config.FlushInterval)
	defer ticker.Stop()
	
	flushBatch := func() {
		if len(batch.events) == 0 {
			return
		}
		
		// Send batch to writer
		select {
		case s.eventChan <- batch:
		case <-s.ctx.Done():
			return
		}
		
		// Reset batch
		batch = eventBatch{
			events: make([]models.SecurityEvent, 0, s.config.BatchSize),
			msgs:   make([]amqp.Delivery, 0, s.config.BatchSize),
		}
	}
	
	for {
		select {
		case <-s.ctx.Done():
			flushBatch()
			return
			
		case msg, ok := <-msgs:
			if !ok {
				flushBatch()
				return
			}
			
			// Parse message (expects array from enrichment service)
			var events []models.SecurityEvent
			if err := json.Unmarshal(msg.Body, &events); err != nil {
				// Try single event
				var single models.SecurityEvent
				if err := json.Unmarshal(msg.Body, &single); err != nil {
					log.Printf("Failed to parse message: %v", err)
					msg.Nack(false, false)
					atomic.AddUint64(&s.stats.Errors, 1)
					continue
				}
				events = []models.SecurityEvent{single}
			}
			
			atomic.AddUint64(&s.stats.EventsReceived, uint64(len(events)))
			
			// Add to batch
			batch.events = append(batch.events, events...)
			batch.msgs = append(batch.msgs, msg)
			
			// Flush if batch is full
			if len(batch.events) >= s.config.BatchSize {
				flushBatch()
			}
			
		case <-ticker.C:
			flushBatch()
		}
	}
}

// writerWorker writes batches to database
func (s *Service) writerWorker(id int) {
	defer s.wg.Done()
	
	log.Printf("DB writer worker %d started", id)
	
	for {
		select {
		case <-s.ctx.Done():
			return
		case batch, ok := <-s.eventChan:
			if !ok {
				return
			}
			
			s.writeBatch(batch)
		}
	}
}

func (s *Service) writeBatch(batch eventBatch) {
	if len(batch.events) == 0 {
		return
	}
	
	start := time.Now()
	
	// Try insert with retries
	var lastErr error
	for attempt := 0; attempt < s.config.MaxRetries; attempt++ {
		ctx, cancel := context.WithTimeout(s.ctx, 30*time.Second)
		err := s.db.InsertEvents(ctx, batch.events)
		cancel()
		
		if err == nil {
			// Success - ACK all messages
			for _, msg := range batch.msgs {
				msg.Ack(false)
			}
			
			atomic.AddUint64(&s.stats.EventsInserted, uint64(len(batch.events)))
			atomic.AddUint64(&s.stats.BatchesWritten, 1)
			
			elapsed := time.Since(start).Milliseconds()
			atomic.StoreInt64(&s.stats.AvgBatchTimeMs, elapsed)
			
			return
		}
		
		lastErr = err
		atomic.AddUint64(&s.stats.RetryCount, 1)
		log.Printf("Batch insert failed (attempt %d/%d): %v", attempt+1, s.config.MaxRetries, err)
		
		// Exponential backoff
		time.Sleep(time.Duration(attempt+1) * time.Second)
	}
	
	// All retries failed - NACK to requeue
	log.Printf("Batch insert failed after %d retries: %v", s.config.MaxRetries, lastErr)
	atomic.AddUint64(&s.stats.Errors, 1)
	
	for _, msg := range batch.msgs {
		msg.Nack(false, true) // Requeue
	}
}

func (s *Service) reportStats() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			received := atomic.LoadUint64(&s.stats.EventsReceived)
			inserted := atomic.LoadUint64(&s.stats.EventsInserted)
			batches := atomic.LoadUint64(&s.stats.BatchesWritten)
			errors := atomic.LoadUint64(&s.stats.Errors)
			retries := atomic.LoadUint64(&s.stats.RetryCount)
			avgTime := atomic.LoadInt64(&s.stats.AvgBatchTimeMs)
			
			log.Printf("[DBWriter] Received: %d, Inserted: %d, Batches: %d, Errors: %d, Retries: %d, AvgBatchTime: %dms",
				received, inserted, batches, errors, retries, avgTime)
		}
	}
}

// Stop gracefully stops the DB writer service
func (s *Service) Stop() {
	log.Println("Stopping DB writer service...")
	s.cancel()
	
	// Wait for writers to finish with timeout
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()
	
	select {
	case <-done:
		log.Println("DB writer service stopped gracefully")
	case <-time.After(60 * time.Second): // Longer timeout for DB writes
		log.Println("DB writer service stop timed out")
	}
}

// Stats returns current service statistics
func (s *Service) Stats() ServiceStats {
	return ServiceStats{
		EventsReceived: atomic.LoadUint64(&s.stats.EventsReceived),
		EventsInserted: atomic.LoadUint64(&s.stats.EventsInserted),
		BatchesWritten: atomic.LoadUint64(&s.stats.BatchesWritten),
		Errors:         atomic.LoadUint64(&s.stats.Errors),
		RetryCount:     atomic.LoadUint64(&s.stats.RetryCount),
		AvgBatchTimeMs: atomic.LoadInt64(&s.stats.AvgBatchTimeMs),
	}
}
