package main

import (
	"context"
	"fmt"
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

// Logger interface for logging
type Logger interface {
	Infof(format string, args ...interface{})
	Errorf(format string, args ...interface{})
	Warnf(format string, args ...interface{})
}

// Config stores the application settings
type Config struct {
	PodName         string
	MonitorURL      string
	MonitorInterval int
}

// NewConfig creates a new configuration instance from environment variables
func NewConfig(logger Logger) *Config {
	viper.AutomaticEnv()
	viper.SetEnvPrefix("app")
	viper.BindEnv("POD_NAME")
	viper.BindEnv("MONITOR_URL")
	viper.BindEnv("MONITOR_INTERVAL")

	viper.SetDefault("MONITOR_INTERVAL", 20) // 20 seconds

	cfg := &Config{
		PodName:         viper.GetString("POD_NAME"),
		MonitorURL:      viper.GetString("MONITOR_URL"),
		MonitorInterval: viper.GetInt("MONITOR_INTERVAL"),
	}

	if err := cfg.Validate(logger); err != nil {
		logger.Errorf("Invalid configuration: %v", err)
	}

	return cfg
}

// Validate checks the configuration for any invalid values
func (cfg *Config) Validate(logger Logger) error {
	if cfg.MonitorURL == "" {
		logger.Warnf("Monitor URL is empty. Monitoring will not be started.")
	} else if _, err := url.ParseRequestURI(cfg.MonitorURL); err != nil {
		return fmt.Errorf("invalid monitor URL: %v", err)
	}
	if cfg.MonitorInterval <= 0 {
		return fmt.Errorf("invalid monitor interval, must be greater than zero")
	}
	return nil
}

// Monitor handles the monitoring of a given URL at specified intervals
type Monitor struct {
	URL      string
	Interval int
	Logger   Logger
}

// Start begins the monitoring process
func (m *Monitor) Start() {
	ticker := time.NewTicker(time.Duration(m.Interval) * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		response, err := http.Get(m.URL)
		if err != nil {
			m.Logger.Errorf("Failed to reach monitor target: %v", err)
			continue
		}

		m.Logger.Infof("Success: status code %d for monitor URL %s", response.StatusCode, m.URL)
		response.Body.Close()
	}
}

// setupRoutes configures the HTTP routes for the application
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

// setSecurityHeaders adds security-related headers to all responses
func setSecurityHeaders(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		c.Response().Header().Set("X-XSS-Protection", "1; mode=block")
		c.Response().Header().Set("X-Content-Type-Options", "nosniff")
		c.Response().Header().Set("Content-Security-Policy", "default-src 'self'")
		return next(c)
	}
}

// main is the entry point of the application
func main() {
	e := echo.New()
	config := NewConfig(e.Logger)

	e.Use(middleware.Logger(), middleware.Recover(), setSecurityHeaders, middleware.CSRFWithConfig(middleware.CSRFConfig{
		TokenLookup: "header:X-XSRF-TOKEN",
		CookiePath:  "/",
	}))

	p := prometheus.NewPrometheus("echo", nil)
	p.Use(e)

	setupRoutes(e, config)

	if config.MonitorURL != "" {
		monitor := Monitor{
			URL:      config.MonitorURL,
			Interval: config.MonitorInterval,
			Logger:   e.Logger,
		}
		go monitor.Start()
	} else {
		e.Logger.Warnf("Monitor URL is empty, skipping monitoring process.")
	}

	startServer(e)
}

// startServer initializes and starts the HTTP server
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
