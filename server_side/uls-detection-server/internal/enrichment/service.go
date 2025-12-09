package enrichment

import (
	"context"
	"encoding/json"
	"log"
	"sync"
	"sync/atomic"
	"time"

	amqp "github.com/rabbitmq/amqp091-go"

	"uls-detection-server/internal/detector"
	"uls-detection-server/internal/models"
	"uls-detection-server/internal/queue"
)

// ServiceConfig holds enrichment service configuration
type ServiceConfig struct {
	NumWorkers    int
	SourceQueue   string
	TargetQueue   string
	Prefetch      int
	PublishBatch  int
}

// Service handles event enrichment with worker pool
type Service struct {
	config     ServiceConfig
	consumer   *queue.Consumer
	publisher  *queue.Publisher
	detector   *detector.Detector
	
	// Channels
	eventChan    chan eventDelivery
	enrichedChan chan *models.EnrichedEvent
	
	// Control
	ctx        context.Context
	cancel     context.CancelFunc
	wg         sync.WaitGroup
	
	// Metrics
	stats      *ServiceStats
}

type eventDelivery struct {
	events []models.SecurityEvent
	msg    amqp.Delivery
}

// ServiceStats tracks enrichment metrics
type ServiceStats struct {
	EventsReceived   uint64
	EventsEnriched   uint64
	EventsPublished  uint64
	Errors           uint64
	AvgEnrichTimeUs  int64
}

// NewService creates a new enrichment service
func NewService(
	consumer *queue.Consumer,
	publisher *queue.Publisher,
	det *detector.Detector,
	config ServiceConfig,
) *Service {
	ctx, cancel := context.WithCancel(context.Background())
	
	return &Service{
		config:       config,
		consumer:     consumer,
		publisher:    publisher,
		detector:     det,
		eventChan:    make(chan eventDelivery, config.Prefetch*2),
		enrichedChan: make(chan *models.EnrichedEvent, config.Prefetch*config.NumWorkers),
		ctx:          ctx,
		cancel:       cancel,
		stats:        &ServiceStats{},
	}
}

// Start begins the enrichment pipeline
func (s *Service) Start() error {
	log.Printf("Starting enrichment service with %d workers", s.config.NumWorkers)
	
	// Start message receiver
	s.wg.Add(1)
	go s.receiveMessages()
	
	// Start worker pool
	for i := 0; i < s.config.NumWorkers; i++ {
		s.wg.Add(1)
		go s.enrichmentWorker(i)
	}
	
	// Start publisher
	s.wg.Add(1)
	go s.publishWorker()
	
	// Start stats reporter
	go s.reportStats()
	
	return nil
}

// receiveMessages pulls from RabbitMQ and distributes to workers
func (s *Service) receiveMessages() {
	defer s.wg.Done()
	
	msgs, err := s.consumer.Consume()
	if err != nil {
		log.Printf("Failed to start consuming: %v", err)
		return
	}
	
	for {
		select {
		case <-s.ctx.Done():
			return
		case msg, ok := <-msgs:
			if !ok {
				log.Println("Consumer channel closed")
				return
			}
			
			// Parse message
			var events []models.SecurityEvent
			if err := json.Unmarshal(msg.Body, &events); err != nil {
				// Try single event
				var single models.SecurityEvent
				if err := json.Unmarshal(msg.Body, &single); err != nil {
					log.Printf("Failed to parse message: %v", err)
					msg.Nack(false, false) // Don't requeue malformed
					atomic.AddUint64(&s.stats.Errors, 1)
					continue
				}
				events = []models.SecurityEvent{single}
			}
			
			atomic.AddUint64(&s.stats.EventsReceived, uint64(len(events)))
			
			// Send to worker pool
			select {
			case s.eventChan <- eventDelivery{events: events, msg: msg}:
			case <-s.ctx.Done():
				return
			}
		}
	}
}

// enrichmentWorker processes events and applies detection rules
func (s *Service) enrichmentWorker(id int) {
	defer s.wg.Done()
	
	log.Printf("Enrichment worker %d started", id)
	
	for {
		select {
		case <-s.ctx.Done():
			return
		case delivery, ok := <-s.eventChan:
			if !ok {
				return
			}
			
			// Process each event
			for i := range delivery.events {
				start := time.Now()
				
				// Apply detection
				result := s.detector.Detect(&delivery.events[i])
				
				// Create enriched event
				enriched := &models.EnrichedEvent{
					Event:           delivery.events[i],
					Severity:        result.Severity,
					MitreTechnique:  result.MitreTechnique,
					DetectionModule: result.DetectionModule,
					EventDetails:    result.EventDetails,
					EnrichmentTime:  time.Since(start),
				}
				
				// Update event fields
				enriched.Event.Severity = result.Severity
				enriched.Event.MitreTechnique = result.MitreTechnique
				enriched.Event.DetectionModule = result.DetectionModule
				enriched.Event.EventDetails = result.EventDetails
				enriched.Event.AdditionalContext = result.AdditionalContext
				
				// Send to publisher
				select {
				case s.enrichedChan <- enriched:
					atomic.AddUint64(&s.stats.EventsEnriched, 1)
				case <-s.ctx.Done():
					return
				}
			}
			
			// ACK after enrichment (before DB write)
			delivery.msg.Ack(false)
		}
	}
}

// publishWorker batches and publishes enriched events to second queue
func (s *Service) publishWorker() {
	defer s.wg.Done()
	
	batch := make([]*models.EnrichedEvent, 0, s.config.PublishBatch)
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	
	for {
		select {
		case <-s.ctx.Done():
			// Flush remaining
			if len(batch) > 0 {
				s.publishBatch(batch)
			}
			return
			
		case enriched, ok := <-s.enrichedChan:
			if !ok {
				return
			}
			
			batch = append(batch, enriched)
			
			// Publish when batch is full
			if len(batch) >= s.config.PublishBatch {
				s.publishBatch(batch)
				batch = batch[:0]
			}
			
		case <-ticker.C:
			// Flush partial batch on timer
			if len(batch) > 0 {
				s.publishBatch(batch)
				batch = batch[:0]
			}
		}
	}
}

func (s *Service) publishBatch(batch []*models.EnrichedEvent) {
	if len(batch) == 0 {
		return
	}
	
	// Extract just the events for publishing
	events := make([]models.SecurityEvent, len(batch))
	for i, e := range batch {
		events[i] = e.Event
	}
	
	ctx, cancel := context.WithTimeout(s.ctx, 10*time.Second)
	defer cancel()
	
	if err := s.publisher.Publish(ctx, events); err != nil {
		log.Printf("Failed to publish batch: %v", err)
		atomic.AddUint64(&s.stats.Errors, 1)
		// Events will be reprocessed from source queue on failure
		return
	}
	
	atomic.AddUint64(&s.stats.EventsPublished, uint64(len(batch)))
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
			enriched := atomic.LoadUint64(&s.stats.EventsEnriched)
			published := atomic.LoadUint64(&s.stats.EventsPublished)
			errors := atomic.LoadUint64(&s.stats.Errors)
			
			log.Printf("[Enrichment] Received: %d, Enriched: %d, Published: %d, Errors: %d",
				received, enriched, published, errors)
		}
	}
}

// Stop gracefully stops the enrichment service
func (s *Service) Stop() {
	log.Println("Stopping enrichment service...")
	s.cancel()
	
	// Close channels to signal workers
	close(s.eventChan)
	
	// Wait for workers with timeout
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()
	
	select {
	case <-done:
		log.Println("Enrichment service stopped gracefully")
	case <-time.After(30 * time.Second):
		log.Println("Enrichment service stop timed out")
	}
}

// Stats returns current service statistics
func (s *Service) Stats() ServiceStats {
	return ServiceStats{
		EventsReceived:  atomic.LoadUint64(&s.stats.EventsReceived),
		EventsEnriched:  atomic.LoadUint64(&s.stats.EventsEnriched),
		EventsPublished: atomic.LoadUint64(&s.stats.EventsPublished),
		Errors:          atomic.LoadUint64(&s.stats.Errors),
	}
}
