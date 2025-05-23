package codec

import (
	"context"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/google/uuid"
	"go.temporal.io/sdk/activity"
	"go.temporal.io/sdk/workflow"
)

// Workflow is a standard workflow definition.
// Note that the Workflow and Activity don't need to care that
// their inputs/results are being encoded.
func Workflow(ctx workflow.Context, input string) (string, error) {
	ao := workflow.ActivityOptions{
		StartToCloseTimeout: 10 * time.Second,
	}
	lao := workflow.LocalActivityOptions{
		StartToCloseTimeout: 10 * time.Second,
	}
	ctx = workflow.WithActivityOptions(ctx, ao)
	ctx = workflow.WithLocalActivityOptions(ctx, lao)

	logger := workflow.GetLogger(ctx)
	logger.Info("Codec Server workflow started", "input", input)

	var result string

	err := workflow.SideEffect(ctx, func(ctx workflow.Context) interface{} {
		return uuid.New()
	}).Get(&result)
	if err != nil {
		logger.Error("SideEffect failed.", "Error", err)
		return "", err
	}

	err = workflow.ExecuteLocalActivity(ctx, Activity, input).Get(ctx, &result)
	if err != nil {
		logger.Error("Local Activity failed.", "Error", err)
		return "", err
	}

	err = workflow.ExecuteActivity(ctx, Activity, input).Get(ctx, &result)
	if err != nil {
		logger.Error("Activity failed.", "Error", err)
		return "", err
	}

	workflow.Sleep(ctx, 10*time.Second)
	logger.Info("Codec Server workflow slept for 10 seconds, about to attempt /timeout activity.")

	err = workflow.ExecuteActivity(ctx, TimeoutActivity, input).Get(ctx, &result)
	if err != nil {
		logger.Error("TimeoutActivity failed.", "Error", err)
		return "", err
	}

	logger.Info("Codec Server workflow completed.", "result", result)

	return result, nil
}

func Activity(ctx context.Context, input string) (string, error) {
	logger := activity.GetLogger(ctx)
	logger.Info("Activity", "input", input)

	return "Received " + input, nil
}

func TimeoutActivity(ctx context.Context, expenseID string) error {

	resp, err := http.Get("http://localhost:5173/timeout")
	if err != nil {
		return err
	}
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil {
		return err
	}

	if string(body) == "SUCCEED" {
		activity.GetLogger(ctx).Info("Expense created.", "ExpenseID", expenseID)
		return nil
	}

	return errors.New(string(body))
}
