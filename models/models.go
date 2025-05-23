package models

import (
	"time"

	commonpb "go.temporal.io/api/common/v1"
)

// Payload represents the structure of a Temporal payload
type Payload struct {
	Metadata map[string]string `json:"metadata"`
	Data     string            `json:"data"`
}

// PayloadData represents the structure of data within a Temporal payload
type PayloadData struct {
	Data         interface{} `json:"data"`
	Timeout      int         `json:"timeout,omitempty"` // Timeout in seconds, optional
	ActivityID   string      `json:"ActivityID,omitempty"`
	ActivityType string      `json:"ActivityType,omitempty"`
	ReplayTime   string      `json:"ReplayTime,omitempty"`
	Attempt      int         `json:"Attempt,omitempty"`
	Backoff      int         `json:"Backoff,omitempty"`
}

// CodecRequest represents the request body for encode/decode operations
type CodecRequest struct {
	Payloads []*commonpb.Payload `json:"payloads"`
}

// CodecResponse represents the response body for encode/decode operations
type CodecResponse struct {
	Payloads []*commonpb.Payload `json:"payloads"`
}

// Config holds the server configuration
type Config struct {
	Port            string
	DefaultTimeout  time.Duration
	SimulateTimeout bool
	KeyID           string
	Keys            map[string][]byte
}
