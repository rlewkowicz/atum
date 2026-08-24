package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"atum/cli/command"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := command.New(command.Options{}).ExecuteContext(ctx); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
