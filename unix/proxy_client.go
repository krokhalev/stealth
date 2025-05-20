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

type ProxyClient struct {
	Port         int                `json:"port"`
	Logger       *logrus.Logger     `json:"-"`
	WaitGroup    *sync.WaitGroup    `json:"-"`
	InitChan     chan struct{}      `json:"-"`
	ErrChan      chan error         `json:"-"`
	Ctx          context.Context    `json:"-"`
	Cancel       context.CancelFunc `json:"-"`
	ProcessNames []string           `json:"process_names"`
}

func NewProxyClient() *ProxyClient {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	return &ProxyClient{
		Port:         12345,
		Logger:       logrus.New(),
		WaitGroup:    new(sync.WaitGroup),
		InitChan:     make(chan struct{}, 1),
		ErrChan:      make(chan error, 1),
		Ctx:          ctx,
		Cancel:       cancel,
		ProcessNames: []string{"discord", "brave"},
	}
}

func main() {
	PC := NewProxyClient()
	defer PC.Cancel()
	PC.Start()
}

func (PC *ProxyClient) Start() {
	go PC.Init()
	<-PC.InitChan
	PC.Logger.Info("[+] Init done")

	go PC.ginServer()

	select {
	case <-PC.Ctx.Done():
		PC.Logger.Info("[!] Shutting down gracefully")
	case err := <-PC.ErrChan:
		PC.Logger.Errorf("[-] Client exited with error: %v", err)
		PC.Cleanup()
	}

	PC.WaitGroup.Wait()
}

func (PC *ProxyClient) ginServer() {
	client := gin.New()
	client.Use(gin.LoggerWithWriter(PC.Logger.Writer(), "/status", "/metrics", "/health"), gin.Recovery())
	client.GET("/ping", func(c *gin.Context) {
		c.JSON(http.StatusOK, map[string]string{"message": "pong"})
	})
	go func() {
		err := client.Run("localhost:" + fmt.Sprint(PC.Port))
		if err != nil {
			PC.ErrChan <- fmt.Errorf("failed to run client: %v", err)
		}
	}()
}
