package main

import (
	"fmt"
	"net/http"
	"time"

	internal "github.com/thomseddon/traefik-forward-auth/internal"
)

// Main
func main() {
	// Parse options
	config := internal.NewGlobalConfig()

	// Setup logger
	log := internal.NewDefaultLogger()

	// Perform config validation
	config.Validate()

	// Build server
	server := internal.NewServer()

	// Attach router to default server
	http.HandleFunc("/", server.RootHandler)

	httpServer := &http.Server{
		Addr:              fmt.Sprintf(":%d", config.Port),
		Handler:           nil,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}

	// Start
	log.WithField("config", config).Debug("Starting with config")
	log.Infof("Listening on :%d", config.Port)
	log.Info(httpServer.ListenAndServe())
}
