package codec

import (
	"bytes"
	"codec-server/models"
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

func (c *HTTPCodec) Encode(payloads []*commonpb.Payload) ([]*commonpb.Payload, error) {
	// Send request to codec server
	reqBody, err := json.Marshal(models.CodecRequest{Payloads: payloads})
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

	var codecResp models.CodecResponse
	if err := json.NewDecoder(resp.Body).Decode(&codecResp); err != nil {
		return nil, fmt.Errorf("failed to decode response: %v", err)
	}

	return codecResp.Payloads, nil
}

func (c *HTTPCodec) Decode(payloads []*commonpb.Payload) ([]*commonpb.Payload, error) {
	// Send request to codec server
	reqBody, err := json.Marshal(models.CodecRequest{Payloads: payloads})
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

	var codecResp models.CodecResponse
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
