package main

import (
	codec "codec-server/codec"
	"context"
	"log"

	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/converter"
	"go.temporal.io/sdk/workflow"
)

func main() {

	// Create the codec instance
	cInstance := codec.New("http://localhost:8081")

	// Create a data converter that uses our codec
	dataConverter := converter.NewCodecDataConverter(
		converter.GetDefaultDataConverter(),
		cInstance,
	)

	// Create a data converter without deadlock detection
	dataConverterWithoutDeadlock := workflow.DataConverterWithoutDeadlockDetection(dataConverter)

	c, err := client.Dial(client.Options{
		HostPort:      "localhost:7233",
		Namespace:     "default",
		DataConverter: dataConverterWithoutDeadlock,
	})

	if err != nil {
		log.Fatalln("Unable to create client", err)
	}
	defer c.Close()

	workflowOptions := client.StartWorkflowOptions{
		ID:        "codecserver_workflowID",
		TaskQueue: "codecserver",
	}

	// The workflow input "My Compressed Friend" will be encoded by the codec before being sent to Temporal
	we, err := c.ExecuteWorkflow(
		context.Background(),
		workflowOptions,
		codec.Workflow,
		"Plain text input",
	)
	if err != nil {
		log.Fatalln("Unable to execute workflow", err)
	}

	log.Println("Started workflow", "WorkflowID", we.GetID(), "RunID", we.GetRunID())

	// Synchronously wait for the workflow completion.
	var result string
	err = we.Get(context.Background(), &result)
	if err != nil {
		log.Fatalln("Unable get workflow result", err)
	}
	log.Println("Workflow result:", result)
}
