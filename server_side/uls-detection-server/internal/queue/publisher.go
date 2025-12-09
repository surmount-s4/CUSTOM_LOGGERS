package queue

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	amqp "github.com/rabbitmq/amqp091-go"
)

// Publisher handles RabbitMQ message publishing
type Publisher struct {
	conn       *amqp.Connection
	channel    *amqp.Channel
	queue      string
	mu         sync.Mutex
	confirms   chan amqp.Confirmation
	connected  bool
	connString string

	// Reconnection
	reconnectMu   sync.Mutex
	reconnecting  bool
	notifyClose   chan *amqp.Error
	notifyConfirm chan amqp.Confirmation
}

// NewPublisher creates a new RabbitMQ publisher with confirms enabled
func NewPublisher(host, port, user, pass, queueName string) (*Publisher, error) {
	connStr := fmt.Sprintf("amqp://%s:%s@%s:%s/", user, pass, host, port)

	p := &Publisher{
		queue:      queueName,
		connString: connStr,
	}

	if err := p.connect(); err != nil {
		return nil, err
	}

	// Start reconnection handler
	go p.handleReconnect()

	return p, nil
}

func (p *Publisher) connect() error {
	p.mu.Lock()
	defer p.mu.Unlock()

	conn, err := amqp.Dial(p.connString)
	if err != nil {
		return fmt.Errorf("failed to connect to RabbitMQ: %w", err)
	}

	ch, err := conn.Channel()
	if err != nil {
		conn.Close()
		return fmt.Errorf("failed to open channel: %w", err)
	}

	// Enable publisher confirms
	if err := ch.Confirm(false); err != nil {
		ch.Close()
		conn.Close()
		return fmt.Errorf("failed to enable confirms: %w", err)
	}

	// Declare queue
	_, err = ch.QueueDeclare(
		p.queue,
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

	p.conn = conn
	p.channel = ch
	p.connected = true

	// Setup notifications
	p.notifyClose = make(chan *amqp.Error, 1)
	p.notifyConfirm = make(chan amqp.Confirmation, 100)
	p.channel.NotifyClose(p.notifyClose)
	p.channel.NotifyPublish(p.notifyConfirm)

	log.Printf("Publisher connected to queue: %s", p.queue)

	return nil
}

func (p *Publisher) handleReconnect() {
	for {
		select {
		case err := <-p.notifyClose:
			if err != nil {
				log.Printf("Publisher connection lost: %v, reconnecting...", err)
				p.reconnect()
			}
		}
	}
}

func (p *Publisher) reconnect() {
	p.reconnectMu.Lock()
	if p.reconnecting {
		p.reconnectMu.Unlock()
		return
	}
	p.reconnecting = true
	p.reconnectMu.Unlock()

	defer func() {
		p.reconnectMu.Lock()
		p.reconnecting = false
		p.reconnectMu.Unlock()
	}()

	p.connected = false

	for attempt := 1; attempt <= 30; attempt++ {
		log.Printf("Reconnection attempt %d/30...", attempt)

		if err := p.connect(); err != nil {
			log.Printf("Reconnection failed: %v", err)
			time.Sleep(time.Duration(attempt) * time.Second)
			continue
		}

		log.Println("Publisher reconnected successfully")
		return
	}

	log.Fatal("Failed to reconnect after 30 attempts")
}

// Publish sends a message to the queue with confirmation
func (p *Publisher) Publish(ctx context.Context, data interface{}) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	if !p.connected {
		return fmt.Errorf("publisher not connected")
	}

	body, err := json.Marshal(data)
	if err != nil {
		return fmt.Errorf("failed to marshal data: %w", err)
	}

	err = p.channel.PublishWithContext(
		ctx,
		"",      // exchange
		p.queue, // routing key
		false,   // mandatory
		false,   // immediate
		amqp.Publishing{
			DeliveryMode: amqp.Persistent,
			ContentType:  "application/json",
			Body:         body,
			Timestamp:    time.Now(),
		},
	)
	if err != nil {
		return fmt.Errorf("failed to publish message: %w", err)
	}

	// Wait for confirmation with timeout
	select {
	case confirm := <-p.notifyConfirm:
		if !confirm.Ack {
			return fmt.Errorf("message not confirmed by broker")
		}
	case <-time.After(5 * time.Second):
		return fmt.Errorf("confirmation timeout")
	case <-ctx.Done():
		return ctx.Err()
	}

	return nil
}

// PublishBatch sends multiple messages efficiently
func (p *Publisher) PublishBatch(ctx context.Context, items []interface{}) error {
	for _, item := range items {
		if err := p.Publish(ctx, item); err != nil {
			return err
		}
	}
	return nil
}

// IsConnected returns the connection status
func (p *Publisher) IsConnected() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.connected
}

// Close closes the publisher connection
func (p *Publisher) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.channel != nil {
		p.channel.Close()
	}
	if p.conn != nil {
		p.conn.Close()
	}
	p.connected = false
	log.Println("Publisher connection closed")
}
