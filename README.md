# Temporal Codec Server

A Go implementation of a Temporal Codec server that provides encryption and decryption capabilities for Temporal payloads. This server implements the [Temporal Codec Server specification](https://docs.temporal.io/production-deployment/data-encryption).

## Features

- `/encode` endpoint for encrypting payloads using AES-GCM
- `/decode` endpoint for decrypting payloads
- Configurable timeout simulation for testing
- CORS support for Temporal Web UI integration
- Health check endpoint
- Key rotation support via key IDs

## Security

The server uses AES-GCM encryption with:
- 256-bit key size
- Secure random nonce generation
- Authenticated encryption
- Base64 encoding for transport
- Key rotation support

## Configuration

The server can be configured using environment variables:

- `PORT`: Server port (default: "8080")
- `KEY_ID`: Encryption key identifier (default: "test-key")
- `ENCRYPTION_KEY`: 32-byte encryption key (default: test key, change in production!)

## Using with Temporal Workers

To use this codec server with a Temporal worker, you'll need to:

1. Start the codec server:
```bash
docker-compose up
```

2. In your worker code, create a custom data converter that uses the codec server:

```go
package main

import (
    "bytes"
    "encoding/json"
    "fmt"
    "net/http"

    "go.temporal.io/sdk/converter"
)

type HTTPCodec struct {
    CodecServerURL string
}

func (c *HTTPCodec) Encode(payloads []*converter.Payload) ([]*converter.Payload, error) {
    // Convert payloads to the codec server format
    reqPayloads := make([]Payload, len(payloads))
    for i, p := range payloads {
        reqPayloads[i] = Payload{
            Metadata: make(map[string]string),
            Data:     string(p.Data),
        }
        for k, v := range p.Metadata {
            reqPayloads[i].Metadata[k] = string(v)
        }
    }

    // Send request to codec server
    reqBody, err := json.Marshal(CodecRequest{Payloads: reqPayloads})
    if err != nil {
        return nil, fmt.Errorf("failed to marshal request: %v", err)
    }

    resp, err := http.Post(c.CodecServerURL+"/encode", "application/json", bytes.NewBuffer(reqBody))
    if err != nil {
        return nil, fmt.Errorf("failed to send request: %v", err)
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        return nil, fmt.Errorf("codec server returned error: %s", resp.Status)
    }

    var codecResp CodecResponse
    if err := json.NewDecoder(resp.Body).Decode(&codecResp); err != nil {
        return nil, fmt.Errorf("failed to decode response: %v", err)
    }

    // Convert response back to Temporal payloads
    result := make([]*converter.Payload, len(codecResp.Payloads))
    for i, p := range codecResp.Payloads {
        result[i] = &converter.Payload{
            Metadata: make(map[string][]byte),
            Data:     []byte(p.Data),
        }
        for k, v := range p.Metadata {
            result[i].Metadata[k] = []byte(v)
        }
    }

    return result, nil
}

func (c *HTTPCodec) Decode(payloads []*converter.Payload) ([]*converter.Payload, error) {
    // Convert payloads to the codec server format
    reqPayloads := make([]Payload, len(payloads))
    for i, p := range payloads {
        reqPayloads[i] = Payload{
            Metadata: make(map[string]string),
            Data:     string(p.Data),
        }
        for k, v := range p.Metadata {
            reqPayloads[i].Metadata[k] = string(v)
        }
    }

    // Send request to codec server
    reqBody, err := json.Marshal(CodecRequest{Payloads: reqPayloads})
    if err != nil {
        return nil, fmt.Errorf("failed to marshal request: %v", err)
    }

    resp, err := http.Post(c.CodecServerURL+"/decode", "application/json", bytes.NewBuffer(reqBody))
    if err != nil {
        return nil, fmt.Errorf("failed to send request: %v", err)
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK {
        return nil, fmt.Errorf("codec server returned error: %s", resp.Status)
    }

    var codecResp CodecResponse
    if err := json.NewDecoder(resp.Body).Decode(&codecResp); err != nil {
        return nil, fmt.Errorf("failed to decode response: %v", err)
    }

    // Convert response back to Temporal payloads
    result := make([]*converter.Payload, len(codecResp.Payloads))
    for i, p := range codecResp.Payloads {
        result[i] = &converter.Payload{
            Metadata: make(map[string][]byte),
            Data:     []byte(p.Data),
        }
        for k, v := range p.Metadata {
            result[i].Metadata[k] = []byte(v)
        }
    }

    return result, nil
}

// Use in your worker:
func main() {
    codec := &HTTPCodec{
        CodecServerURL: "http://localhost:8080",
    }

    // Create a data converter that uses our codec
    dataConverter := converter.NewCodecDataConverter(
        converter.GetDefaultDataConverter(),
        codec,
    )

    // Create a data converter without deadlock detection
    // This is recommended when using custom data converters to avoid potential deadlocks
    dataConverterWithoutDeadlock := converter.DataConverterWithoutDeadlockDetection(dataConverter)

    c, err := client.NewClient(client.Options{
        HostPort:      "localhost:7233",
        Namespace:     "default",
        DataConverter: dataConverterWithoutDeadlock,
    })
    if err != nil {
        log.Fatalf("Failed to create client: %v", err)
    }
    defer c.Close()

    w := worker.New(c, "your-task-queue", worker.Options{})
    // Register your workflows and activities here
    // ... rest of your worker code ...
}

## Endpoints

### Encode
- **URL**: `/encode`
- **Method**: `POST`
- **Body**: 
```json
{
  "payloads": [{
    "metadata": {
      "encoding": "json/protobuf",
      "messageType": "example.Message"
    },
    "data": "example data"
  }]
}
```

### Decode
- **URL**: `/decode`
- **Method**: `POST`
- **Body**: Same as encode endpoint

### Timeout Control
- **URL**: `/toggle-timeout`
- **Method**: `POST`
- **Description**: Toggles timeout simulation on/off

- **URL**: `/set-timeout`
- **Method**: `POST`
- **Query Parameters**: `duration` (in seconds)
- **Description**: Sets the timeout duration for simulation

### Health Check
- **URL**: `/health`
- **Method**: `GET`
- **Response**: `{"status": "healthy"}`

## Running the Server

1. Install dependencies:
```bash
go mod download
```

2. Set your encryption key (optional, but recommended for production):
```bash
export ENCRYPTION_KEY="your-32-byte-encryption-key"
export KEY_ID="your-key-id"
```

3. Run the server:
```bash
go run main.go
```

## Testing Timeout Simulation

1. Enable timeout simulation:
```bash
curl -X POST http://localhost:8080/toggle-timeout
```

2. Set timeout duration (in seconds):
```bash
curl -X POST "http://localhost:8080/set-timeout?duration=10"
```

3. Test with encode/decode endpoints:
```bash
curl -X POST http://localhost:8080/encode \
  -H "Content-Type: application/json" \
  -d '{"payloads":[{"metadata":{"encoding":"json/protobuf"},"data":"test"}]}'
```

## Security Considerations

1. Always use a strong, unique encryption key in production
2. The encryption key should be at least 32 bytes long
3. Consider using a key management service in production
4. The server should be run in a secure environment with proper access controls
5. Use different key IDs for different environments or key rotation
6. Consider adding authentication to the codec server endpoints
7. Use HTTPS in production 