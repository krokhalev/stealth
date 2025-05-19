package main

import (
	"context"
	"fmt"
	"github.com/gin-gonic/gin"
	"net/http"
	"os/signal"
	"sync"
	"syscall"

	"github.com/sirupsen/logrus"
)

const (
	port = 12345
)

func main() {
	logger := logrus.New()
	var wg sync.WaitGroup

	defer func() {
		if r := recover(); r != nil {
			logger.Printf("[-] Panic caught: %v\n", r)
			Cleanup(&wg, logger)
		}
	}()

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	initDone := make(chan struct{}, 1)
	errChan := make(chan error, 1)
	go Init(ctx, &wg, initDone, logger, errChan)
	<-initDone
	logger.Info("[+] Init done")

	client := gin.New()
	client.Use(gin.LoggerWithWriter(logger.Writer(), "/status", "/metrics", "/health"), gin.Recovery())
	client.GET("/ping", func(c *gin.Context) {
		c.JSON(http.StatusOK, map[string]string{"message": "pong"})
	})
	go func() {
		err := client.Run("localhost:" + fmt.Sprint(port))
		if err != nil {
			errChan <- fmt.Errorf("failed to run client: %v", err)
		}
	}()

	select {
	case <-ctx.Done():
		logger.Info("[!] Shutting down gracefully")
	case err := <-errChan:
		logger.Errorf("[-] Client exited with error: %v", err)
		Cleanup(&wg, logger)
	}

	wg.Wait()
}
