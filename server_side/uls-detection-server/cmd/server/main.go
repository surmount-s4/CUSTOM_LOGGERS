package main

import (
	"context"
	"encoding/json"
	"log"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"uls-detection-server/internal/database"
	"uls-detection-server/internal/detector"
	"uls-detection-server/internal/models"
	"uls-detection-server/internal/queue"
)

// Config holds server configuration
type Config struct {
	// RabbitMQ
	RabbitMQHost  string
	RabbitMQPort  string
	RabbitMQUser  string
	RabbitMQPass  string
	RabbitMQQueue string

	// PostgreSQL
	PostgresHost string
	PostgresPort string
	PostgresUser string
	PostgresPass string
	PostgresDB   string

	// Processing
	BatchSize  int
	BatchDelay time.Duration
}

func loadConfig() Config {
	batchSize, _ := strconv.Atoi(getEnv("BATCH_SIZE", "100"))
	batchDelay, _ := strconv.Atoi(getEnv("BATCH_DELAY_MS", "1000"))

	return Config{
		RabbitMQHost:  getEnv("RABBITMQ_HOST", "localhost"),
		RabbitMQPort:  getEnv("RABBITMQ_PORT", "5672"),
		RabbitMQUser:  getEnv("RABBITMQ_USER", "guest"),
		RabbitMQPass:  getEnv("RABBITMQ_PASS", "guest"),
		RabbitMQQueue: getEnv("RABBITMQ_QUEUE", "security_events"),
		PostgresHost:  getEnv("POSTGRES_HOST", "localhost"),
		PostgresPort:  getEnv("POSTGRES_PORT", "5432"),
		PostgresUser:  getEnv("POSTGRES_USER", "postgres"),
		PostgresPass:  getEnv("POSTGRES_PASS", "postgres"),
		PostgresDB:    getEnv("POSTGRES_DB", "security_logs"),
		BatchSize:     batchSize,
		BatchDelay:    time.Duration(batchDelay) * time.Millisecond,
	}
}

func getEnv(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}

func main() {
	log.Println("Starting ULS Detection Server...")

	cfg := loadConfig()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Connect to PostgreSQL
	db, err := database.Connect(ctx, cfg.PostgresHost, cfg.PostgresPort, cfg.PostgresUser, cfg.PostgresPass, cfg.PostgresDB)
	if err != nil {
		log.Fatalf("Failed to connect to PostgreSQL: %v", err)
	}
	defer db.Close()

	// Initialize schema
	if err := database.InitSchema(ctx, db); err != nil {
		log.Fatalf("Failed to initialize schema: %v", err)
	}

	// Connect to RabbitMQ
	consumer, err := queue.NewConsumer(cfg.RabbitMQHost, cfg.RabbitMQPort, cfg.RabbitMQUser, cfg.RabbitMQPass, cfg.RabbitMQQueue)
	if err != nil {
		log.Fatalf("Failed to connect to RabbitMQ: %v", err)
	}
	defer consumer.Close()

	// Initialize detector
	det := detector.New()

	// Start consuming
	msgs, err := consumer.Consume()
	if err != nil {
		log.Fatalf("Failed to start consuming: %v", err)
	}

	// Handle graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Batch processing
	batch := make([]models.SecurityEvent, 0, cfg.BatchSize)
	ticker := time.NewTicker(cfg.BatchDelay)
	defer ticker.Stop()

	log.Println("Server started, waiting for events...")

	for {
		select {
		case <-sigChan:
			log.Println("Shutdown signal received, processing remaining batch...")
			if len(batch) > 0 {
				processBatch(ctx, db, det, batch)
			}
			log.Println("Server stopped")
			return

		case msg, ok := <-msgs:
			if !ok {
				log.Println("Channel closed, exiting...")
				return
			}

			// Parse message (can be single event or array)
			var events []models.SecurityEvent
			if err := json.Unmarshal(msg.Body, &events); err != nil {
				// Try single event
				var single models.SecurityEvent
				if err := json.Unmarshal(msg.Body, &single); err != nil {
					log.Printf("Failed to parse message: %v", err)
					msg.Nack(false, false)
					continue
				}
				events = []models.SecurityEvent{single}
			}

			batch = append(batch, events...)

			// Process if batch is full
			if len(batch) >= cfg.BatchSize {
				if err := processBatch(ctx, db, det, batch); err != nil {
					log.Printf("Failed to process batch: %v", err)
					msg.Nack(false, true) // Requeue
				} else {
					msg.Ack(false)
				}
				batch = batch[:0]
			} else {
				msg.Ack(false)
			}

		case <-ticker.C:
			// Process partial batch on timer
			if len(batch) > 0 {
				if err := processBatch(ctx, db, det, batch); err != nil {
					log.Printf("Failed to process batch: %v", err)
				}
				batch = batch[:0]
			}
		}
	}
}

func processBatch(ctx context.Context, db *database.DB, det *detector.Detector, events []models.SecurityEvent) error {
	// Apply detection rules to each event
	for i := range events {
		result := det.Detect(&events[i])
		events[i].Severity = result.Severity
		events[i].MitreTechnique = result.MitreTechnique
		events[i].DetectionModule = result.DetectionModule
		events[i].EventDetails = result.EventDetails
		events[i].AdditionalContext = result.AdditionalContext
	}

	// Insert into database
	return db.InsertEvents(ctx, events)
}
