package codec

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"

	commonpb "go.temporal.io/api/common/v1"
)

// HTTPCodec implements the converter.PayloadCodec interface
type HTTPCodec struct {
	CodecServerURL string
}

// Payload represents the structure for codec server communication
type Payload struct {
	Metadata map[string]string `json:"metadata"`
	Data     string            `json:"data"`
}

// CodecRequest represents the request to the codec server
type CodecRequest struct {
	Payloads []*commonpb.Payload `json:"payloads"`
}

// CodecResponse represents the response from the codec server
type CodecResponse struct {
	Payloads []*commonpb.Payload `json:"payloads"`
}

func (c *HTTPCodec) Encode(payloads []*commonpb.Payload) ([]*commonpb.Payload, error) {
	// Send request to codec server
	reqBody, err := json.Marshal(CodecRequest{Payloads: payloads})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %v", err)
	}

	resp, err := http.Post(c.CodecServerURL+"/encode", "application/json", bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		log.Printf("Codec server error - Status: %s, URL: %s, Body: %s", resp.Status, c.CodecServerURL, string(bodyBytes))
		return nil, fmt.Errorf("codec server returned error: %s (URL: %s, Body: %s)", resp.Status, c.CodecServerURL, string(bodyBytes))
	}

	var codecResp CodecResponse
	if err := json.NewDecoder(resp.Body).Decode(&codecResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %v", err)
	}

	return codecResp.Payloads, nil
}

func (c *HTTPCodec) Decode(payloads []*commonpb.Payload) ([]*commonpb.Payload, error) {
	// Send request to codec server
	reqBody, err := json.Marshal(CodecRequest{Payloads: payloads})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %v", err)
	}

	resp, err := http.Post(c.CodecServerURL+"/decoder", "application/json", bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)
		log.Printf("Codec server error - Status: %s, URL: %s, Body: %s", resp.Status, c.CodecServerURL, string(bodyBytes))
		return nil, fmt.Errorf("codec server returned error: %s", resp.Status)
	}

	var codecResp CodecResponse
	if err := json.NewDecoder(resp.Body).Decode(&codecResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %v", err)
	}

	return codecResp.Payloads, nil
}

// New creates a new HTTPCodec instance
func New(serverURL string) *HTTPCodec {
	return &HTTPCodec{
		CodecServerURL: serverURL,
	}
}
