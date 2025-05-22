package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

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

type CodecRequest struct {
	Payloads []*commonpb.Payload `json:"payloads"`
}

// CodecResponse represents the response body for encode/decode operations
type CodecResponse struct {
	Payloads []*commonpb.Payload `json:"payloads"`
}

// Config holds the server configuration
type Config struct {
	Port  string
	KeyID string
	Keys  map[string][]byte
}

var config = Config{
	Port:  getEnv("PORT", "8080"),
	KeyID: getEnv("KEY_ID", "test-key"),
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
