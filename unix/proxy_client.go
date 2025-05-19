package main

import (
	"context"
	"fmt"
	"os/signal"
	"sync"
	"syscall"
)

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	var wg sync.WaitGroup
	go Init(ctx, &wg)

	<-ctx.Done()
	wg.Wait()
	fmt.Printf("[!] Shutting down gracefully\n")
}
