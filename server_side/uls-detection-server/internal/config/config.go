package config

import (
	"os"
	"strconv"
	"time"
)

// Config holds all server configuration
type Config struct {
	// RabbitMQ
	RabbitMQ RabbitMQConfig

	// PostgreSQL
	Postgres PostgresConfig

	// Enrichment Service
	Enrichment EnrichmentConfig

	// DB Writer Service
	DBWriter DBWriterConfig

	// Server
	Server ServerConfig
}

// RabbitMQConfig holds RabbitMQ settings
type RabbitMQConfig struct {
	Host          string
	Port          string
	User          string
	Pass          string
	RawQueue      string // Queue for raw events from agents
	EnrichedQueue string // Queue for enriched events to DB writer
}

// PostgresConfig holds PostgreSQL settings
type PostgresConfig struct {
	Host     string
	Port     string
	User     string
	Pass     string
	Database string
	MaxConns int32
	MinConns int32
}

// EnrichmentConfig holds enrichment service settings
type EnrichmentConfig struct {
	NumWorkers   int
	Prefetch     int
	PublishBatch int
}

// DBWriterConfig holds DB writer service settings
type DBWriterConfig struct {
	NumWorkers    int
	BatchSize     int
	FlushInterval time.Duration
	Prefetch      int
	MaxRetries    int
}

// ServerConfig holds general server settings
type ServerConfig struct {
	Mode         string // "combined", "enrichment", "dbwriter"
	MetricsPort  int
	HealthPort   int
}

// Load reads configuration from environment variables
func Load() Config {
	return Config{
		RabbitMQ: RabbitMQConfig{
			Host:          getEnv("RABBITMQ_HOST", "localhost"),
			Port:          getEnv("RABBITMQ_PORT", "5672"),
			User:          getEnv("RABBITMQ_USER", "guest"),
			Pass:          getEnv("RABBITMQ_PASS", "guest"),
			RawQueue:      getEnv("RABBITMQ_RAW_QUEUE", "security_events_raw"),
			EnrichedQueue: getEnv("RABBITMQ_ENRICHED_QUEUE", "security_events_enriched"),
		},
		Postgres: PostgresConfig{
			Host:     getEnv("POSTGRES_HOST", "localhost"),
			Port:     getEnv("POSTGRES_PORT", "5432"),
			User:     getEnv("POSTGRES_USER", "postgres"),
			Pass:     getEnv("POSTGRES_PASS", "admin"),
			Database: getEnv("POSTGRES_DB", "logs_db"),
			MaxConns: int32(getEnvInt("POSTGRES_MAX_CONNS", 20)),
			MinConns: int32(getEnvInt("POSTGRES_MIN_CONNS", 5)),
		},
		Enrichment: EnrichmentConfig{
			NumWorkers:   getEnvInt("ENRICHMENT_WORKERS", 8),
			Prefetch:     getEnvInt("ENRICHMENT_PREFETCH", 100),
			PublishBatch: getEnvInt("ENRICHMENT_PUBLISH_BATCH", 50),
		},
		DBWriter: DBWriterConfig{
			NumWorkers:    getEnvInt("DBWRITER_WORKERS", 4),
			BatchSize:     getEnvInt("DBWRITER_BATCH_SIZE", 500),
			FlushInterval: time.Duration(getEnvInt("DBWRITER_FLUSH_MS", 500)) * time.Millisecond,
			Prefetch:      getEnvInt("DBWRITER_PREFETCH", 200),
			MaxRetries:    getEnvInt("DBWRITER_MAX_RETRIES", 3),
		},
		Server: ServerConfig{
			Mode:        getEnv("SERVER_MODE", "combined"),
			MetricsPort: getEnvInt("METRICS_PORT", 9090),
			HealthPort:  getEnvInt("HEALTH_PORT", 8080),
		},
	}
}

func getEnv(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}

func getEnvInt(key string, defaultVal int) int {
	if val := os.Getenv(key); val != "" {
		if i, err := strconv.Atoi(val); err == nil {
			return i
		}
	}
	return defaultVal
}
