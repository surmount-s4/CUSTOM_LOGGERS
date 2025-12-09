package queue

import (
	"fmt"
	"log"
	"sync"
	"time"

	amqp "github.com/rabbitmq/amqp091-go"
)

// Consumer handles RabbitMQ message consumption
type Consumer struct {
	conn       *amqp.Connection
	channel    *amqp.Channel
	queue      string
	prefetch   int
	connString string
	
	// Reconnection
	mu           sync.Mutex
	connected    bool
	reconnecting bool
	notifyClose  chan *amqp.Error
}

// ConsumerOption is a functional option for Consumer
type ConsumerOption func(*Consumer)

// WithPrefetch sets the prefetch count
func WithPrefetch(count int) ConsumerOption {
	return func(c *Consumer) {
		c.prefetch = count
	}
}

// NewConsumer creates a new RabbitMQ consumer
func NewConsumer(host, port, user, pass, queueName string, opts ...ConsumerOption) (*Consumer, error) {
	connStr := fmt.Sprintf("amqp://%s:%s@%s:%s/", user, pass, host, port)

	c := &Consumer{
		queue:      queueName,
		prefetch:   100, // Default prefetch (increased from 10)
		connString: connStr,
	}
	
	// Apply options
	for _, opt := range opts {
		opt(c)
	}

	if err := c.connect(); err != nil {
		return nil, err
	}
	
	// Start reconnection handler
	go c.handleReconnect()

	return c, nil
}

func (c *Consumer) connect() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	conn, err := amqp.Dial(c.connString)
	if err != nil {
		return fmt.Errorf("failed to connect to RabbitMQ: %w", err)
	}

	ch, err := conn.Channel()
	if err != nil {
		conn.Close()
		return fmt.Errorf("failed to open channel: %w", err)
	}

	// Declare queue
	_, err = ch.QueueDeclare(
		c.queue,
		true,  // durable
		false, // delete when unused
		false, // exclusive
		false, // no-wait
		amqp.Table{
			"x-queue-type": "classic",
		},
	)
	if err != nil {
		ch.Close()
		conn.Close()
		return fmt.Errorf("failed to declare queue: %w", err)
	}

	// Set prefetch count for better load balancing
	if err := ch.Qos(c.prefetch, 0, false); err != nil {
		ch.Close()
		conn.Close()
		return fmt.Errorf("failed to set QoS: %w", err)
	}

	c.conn = conn
	c.channel = ch
	c.connected = true
	
	// Setup close notification
	c.notifyClose = make(chan *amqp.Error, 1)
	c.channel.NotifyClose(c.notifyClose)

	log.Printf("Consumer connected to RabbitMQ queue: %s (prefetch: %d)", c.queue, c.prefetch)

	return nil
}

func (c *Consumer) handleReconnect() {
	for {
		select {
		case err := <-c.notifyClose:
			if err != nil {
				log.Printf("Consumer connection lost: %v, reconnecting...", err)
				c.reconnect()
			}
		}
	}
}

func (c *Consumer) reconnect() {
	c.mu.Lock()
	if c.reconnecting {
		c.mu.Unlock()
		return
	}
	c.reconnecting = true
	c.connected = false
	c.mu.Unlock()
	
	defer func() {
		c.mu.Lock()
		c.reconnecting = false
		c.mu.Unlock()
	}()

	for attempt := 1; attempt <= 30; attempt++ {
		log.Printf("Consumer reconnection attempt %d/30...", attempt)
		
		if err := c.connect(); err != nil {
			log.Printf("Consumer reconnection failed: %v", err)
			time.Sleep(time.Duration(attempt) * time.Second)
			continue
		}
		
		log.Println("Consumer reconnected successfully")
		return
	}
	
	log.Fatal("Consumer failed to reconnect after 30 attempts")
}

// Consume starts consuming messages from the queue
func (c *Consumer) Consume() (<-chan amqp.Delivery, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	if !c.connected {
		return nil, fmt.Errorf("consumer not connected")
	}
	
	msgs, err := c.channel.Consume(
		c.queue,
		"",    // consumer tag
		false, // auto-ack (false = manual ack)
		false, // exclusive
		false, // no-local
		false, // no-wait
		nil,   // args
	)
	if err != nil {
		return nil, fmt.Errorf("failed to register consumer: %w", err)
	}

	return msgs, nil
}

// IsConnected returns the connection status
func (c *Consumer) IsConnected() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.connected
}

// Close closes the RabbitMQ connection
func (c *Consumer) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	if c.channel != nil {
		c.channel.Close()
	}
	if c.conn != nil {
		c.conn.Close()
	}
	c.connected = false
	log.Println("Consumer connection closed")
}
