package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	commonpb "go.temporal.io/api/common/v1"
	"go.temporal.io/sdk/converter"

	"codec-server/pkg/codec"
)

func getEnv(key, defaultValue string) string {
	if value, exists := os.LookupEnv(key); exists {
		return value
	}
	return defaultValue
}

// Payload represents the structure of a Temporal payload
type Payload struct {
	Metadata map[string]string `json:"metadata"`
	Data     string            `json:"data"`
}

// PayloadData represents the structure of data within a Temporal payload
type PayloadData struct {
	Data    interface{} `json:"data"`
	Timeout int         `json:"timeout,omitempty"` // Timeout in seconds, optional
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

var config = Config{
	Port:            getEnv("PORT", "8080"),
	DefaultTimeout:  5 * time.Second,
	SimulateTimeout: false,
	KeyID:           getEnv("KEY_ID", "test-key"),
	Keys: map[string][]byte{
		"test-key": []byte(getEnv("ENCRYPTION_KEY", "12345678901234567890123456789012")), // 32 bytes for AES-256
	},
}

func main() {
	r := gin.Default()

	// Configure CORS
	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"*"},
		AllowMethods:     []string{"POST", "GET", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "X-Namespace", "Authorization"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
	}))

	// Health check endpoint
	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "healthy"})
	})

	// Toggle timeout simulation
	r.POST("/toggle-timeout", func(c *gin.Context) {
		config.SimulateTimeout = !config.SimulateTimeout
		c.JSON(http.StatusOK, gin.H{
			"simulate_timeout": config.SimulateTimeout,
		})
	})

	// Set timeout duration
	r.POST("/set-timeout", func(c *gin.Context) {
		timeoutStr := c.Query("duration")
		if timeoutStr == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "duration parameter is required"})
			return
		}

		timeout, err := strconv.Atoi(timeoutStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid duration format"})
			return
		}

		config.DefaultTimeout = time.Duration(timeout) * time.Second
		c.JSON(http.StatusOK, gin.H{
			"timeout": config.DefaultTimeout.Seconds(),
		})
	})

	// Create codec instance
	codec := &codec.Codec{
		KeyID: config.KeyID,
		Keys:  config.Keys,
	}

	// Create handler for Temporal's official pattern
	handler := converter.NewPayloadCodecHTTPHandler(codec)

	// Encode endpoint
	r.POST("/encode", handleEncode)

	// Decode endpoint (Temporal's official pattern)
	r.POST("/decode", func(c *gin.Context) {
		// Log the request body
		body, err := c.GetRawData()
		if err != nil {
			log.Printf("Error reading request body: %v", err)
			c.JSON(http.StatusBadRequest, gin.H{"error": "failed to read request body"})
			return
		}
		log.Printf("Received decode request: %s", string(body))

		// Parse the request
		var req CodecRequest
		if err := json.Unmarshal(body, &req); err != nil {
			log.Printf("Error parsing request: %v", err)
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request format"})
			return
		}

		// Convert back to JSON
		newBody, err := json.Marshal(req)
		if err != nil {
			log.Printf("Error marshaling modified request: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to process request"})
			return
		}

		// Restore the body for the handler
		c.Request.Body = io.NopCloser(bytes.NewBuffer(newBody))

		// Call the official handler
		handler.ServeHTTP(c.Writer, c.Request)
	})

	// Decoder endpoint (our custom implementation)
	r.POST("/decoder", handleDecode)

	log.Printf("Starting codec server on port %s", config.Port)
	if err := r.Run(":" + config.Port); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}

func handleEncode(c *gin.Context) {
	var req CodecRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("invalid request format: %v", err)})
		return
	}

	// Encode using the Codec
	codec := &codec.Codec{
		KeyID: config.KeyID,
		Keys:  config.Keys,
	}

	// Process each payload
	for _, payload := range req.Payloads {
		log.Printf("Payload: %+v", payload)
		// Try to extract timeout from payload data
		if len(payload.Data) > 0 {
			// First unmarshal to get the JSON string
			var jsonStr string
			if err := json.Unmarshal(payload.Data, &jsonStr); err == nil {
				// Then unmarshal the actual data structure
				var payloadData PayloadData
				if err := json.Unmarshal([]byte(jsonStr), &payloadData); err == nil {
					log.Printf("Payload data: %+v", payloadData)
					// If timeout is specified and simulation is enabled, apply it
					if payloadData.Timeout > 0 && config.SimulateTimeout {
						time.Sleep(time.Duration(payloadData.Timeout) * time.Second)
					}
				}
			}
		}

	}
	// Encode single payload
	encoded, err := codec.Encode(req.Payloads)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to encode payload: %v", err)})
		return
	}

	// Convert back to response format
	response := CodecResponse{
		Payloads: encoded,
	}
	c.JSON(http.StatusOK, response)
}

func handleDecode(c *gin.Context) {
	var req CodecRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("invalid request format: %v", err)})
		return
	}

	// Decode using the Codec
	codec := &codec.Codec{
		KeyID: config.KeyID,
		Keys:  config.Keys,
	}

	// Process each payload
	for _, payload := range req.Payloads {
		log.Printf("Payload: %+v", payload)
		// Try to extract timeout from payload data
		if len(payload.Data) > 0 {
			// First unmarshal to get the JSON string
			var jsonStr string
			if err := json.Unmarshal(payload.Data, &jsonStr); err == nil {
				// Then unmarshal the actual data structure
				var payloadData PayloadData
				if err := json.Unmarshal([]byte(jsonStr), &payloadData); err == nil {
					log.Printf("Payload data: %+v", payloadData)
					// If timeout is specified and simulation is enabled, apply it
					if payloadData.Timeout > 0 && config.SimulateTimeout {
						time.Sleep(time.Duration(payloadData.Timeout) * time.Second)
					}
				}
			}
		}

	}
	// Decode single payload
	decoded, err := codec.Decode(req.Payloads)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("failed to decode payload: %v", err)})
		return
	}
	// Convert back to response format
	response := CodecResponse{
		Payloads: decoded,
	}
	c.JSON(http.StatusOK, response)
}
