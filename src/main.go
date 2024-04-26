package main

import (
	"context"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/labstack/echo-contrib/prometheus"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"github.com/spf13/viper"
)

type Config struct {
	PodName         string
	MonitorURL      string
	MonitorInterval int
}

func NewConfig() *Config {
	viper.AutomaticEnv()
	viper.SetEnvPrefix("app")
	viper.BindEnv("POD_NAME")
	viper.BindEnv("MONITOR_URL")
	viper.BindEnv("MONITOR_INTERVAL")

	viper.SetDefault("MONITOR_INTERVAL", 20) // 20 секунд

	return &Config{
		PodName:         viper.GetString("POD_NAME"),
		MonitorURL:      viper.GetString("MONITOR_URL"),
		MonitorInterval: viper.GetInt("MONITOR_INTERVAL"),
	}
}

func (cfg *Config) Validate() {
	if _, err := url.ParseRequestURI(cfg.MonitorURL); err != nil {
		log.Printf("Invalid monitor URL: %v", err)
	}

	if cfg.MonitorInterval <= 0 {
		log.Fatalf("Invalid monitor interval, must be greater than zero.")
	}
}

func MonitorTarget(monitorURL string, interval int) {
	ticker := time.NewTicker(time.Duration(interval) * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		response, err := http.Get(monitorURL)
		if err != nil {
			log.Printf("Failed to reach monitor target: %v", err)
			continue
		}

		log.Printf("Success: status code %d for monitor URL %s", response.StatusCode, monitorURL)
		response.Body.Close()
	}
}

func setupRoutes(e *echo.Echo, cfg *Config) {
	e.GET("/healthz", func(c echo.Context) error {
		return c.String(http.StatusOK, "ok")
	})
	e.GET("/readyz", func(c echo.Context) error {
		return c.String(http.StatusOK, "ready")
	})
	e.GET("/", func(c echo.Context) error {
		if cfg.PodName == "" {
			return c.String(http.StatusInternalServerError, "POD_NAME environment variable is not set")
		}
		return c.String(http.StatusOK, cfg.PodName)
	})
}

func setSecurityHeaders(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		c.Response().Header().Set("X-XSS-Protection", "1; mode=block")
		c.Response().Header().Set("X-Content-Type-Options", "nosniff")
		c.Response().Header().Set("Content-Security-Policy", "default-src 'self'")
		return next(c)
	}
}

func main() {
	config := NewConfig()
	config.Validate()

	e := echo.New()
	e.Use(middleware.Logger(), middleware.Recover(), setSecurityHeaders, middleware.CSRFWithConfig(middleware.CSRFConfig{
		TokenLookup: "header:X-XSRF-TOKEN",
		CookiePath:  "/",
	}))

	p := prometheus.NewPrometheus("echo", nil)
	p.Use(e)

	setupRoutes(e, config)

	if config.MonitorURL != "" {
		go MonitorTarget(config.MonitorURL, config.MonitorInterval)
	}

	startServer(e)
}

func startServer(e *echo.Echo) {
	go func() {
		if err := e.Start(":8080"); err != nil && err != http.ErrServerClosed {
			e.Logger.Fatal("shutting down the server")
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := e.Shutdown(ctx); err != nil {
		e.Logger.Fatal(err)
	}
}
