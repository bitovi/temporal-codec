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

## Implementation Details

For detailed implementation examples and usage instructions, see [codec/README.md](codec/README.md).

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

## Security Considerations

1. Always use a strong, unique encryption key in production
2. The encryption key should be at least 32 bytes long
3. Consider using a key management service in production
4. The server should be run in a secure environment with proper access controls
5. Use different key IDs for different environments or key rotation
6. Consider adding authentication to the codec server endpoints
7. Use HTTPS in production 