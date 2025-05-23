package main

import (
	codec "codec-server/codec"
	"log"

	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/converter"
	"go.temporal.io/sdk/worker"
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

	w := worker.New(c, "codecserver", worker.Options{})

	w.RegisterWorkflow(codec.Workflow)
	w.RegisterActivity(codec.Activity)
	w.RegisterActivity(codec.TimeoutActivity)

	err = w.Run(worker.InterruptCh())
	if err != nil {
		log.Fatalln("Unable to start worker", err)
	}
}
