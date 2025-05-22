# Using the Temporal Codec with Your Worker

This guide shows how to integrate the codec server with your Temporal worker for payload encryption.

## Basic Setup

```go
// Create the codec instance
codec := codec.New("http://localhost:8081")

// Create a data converter that uses our codec
dataConverter := converter.NewCodecDataConverter(
	converter.GetDefaultDataConverter(),
	codec,
)

// Create a data converter without deadlock detection
dataConverterWithoutDeadlock := sdkworkflow.DataConverterWithoutDeadlockDetection(dataConverter)

// Create the client
c, err := client.NewClient(client.Options{
	HostPort:      "localhost:7233",
	Namespace:     "default",
	DataConverter: dataConverterWithoutDeadlock,
})
```

## Complete Worker Example

```go
package main

import (
	"log"
	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/worker"
	"go.temporal.io/sdk/converter"
	"go.temporal.io/sdk/workflow"
)

func main() {
	// Create the codec instance
	codec := codec.New("http://localhost:8081")

	// Create a data converter that uses our codec
	dataConverter := converter.NewCodecDataConverter(
		converter.GetDefaultDataConverter(),
		codec,
	)

	// Create a data converter without deadlock detection
	dataConverterWithoutDeadlock := workflow.DataConverterWithoutDeadlockDetection(dataConverter)

	// Create the client
	c, err := client.NewClient(client.Options{
		HostPort:      "localhost:7233",
		Namespace:     "default",
		DataConverter: dataConverterWithoutDeadlock,
	})
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}
	defer c.Close()

	// Create the worker
	w := worker.New(c, "your-task-queue", worker.Options{})

	// Register your workflows and activities
	w.RegisterWorkflow(YourWorkflow)
	w.RegisterActivity(YourActivity)

	// Start the worker
	if err := w.Run(worker.InterruptCh()); err != nil {
		log.Fatalf("Failed to start worker: %v", err)
	}
}
```

## Important Notes

1. The codec server must be running before starting your worker
2. The codec server URL should match your deployment (default: http://localhost:8081)
3. Always use `DataConverterWithoutDeadlockDetection` when using custom data converters
4. Make sure your Temporal server is running and accessible