package main

import (
	"embed"
	"fmt"
	"log"
	"net/http"
	"time"

	"zeek-viz/handlers"
)

const (
	readTimeoutSec  = 15 // HTTP read timeout in seconds
	writeTimeoutSec = 15 // HTTP write timeout in seconds
	idleTimeoutSec  = 60 // HTTP idle timeout in seconds
)

//go:embed static/*
var staticFS embed.FS

func main() {
	// Create API handler without loading connections initially
	api := handlers.NewAPI("")

	// Setup routes
	http.HandleFunc("/", handlers.IndexHandler(staticFS))
	http.Handle("/static/", http.StripPrefix("/static/", handlers.StaticHandler(staticFS)))

	// API routes
	http.HandleFunc("/api/upload", api.UploadFile)
	http.HandleFunc("/api/files", api.GetFiles)
	http.HandleFunc("/api/switch", api.SwitchFile)
	http.HandleFunc("/api/delete", api.DeleteFile)
	http.HandleFunc("/api/connections", api.GetConnections)
	http.HandleFunc("/api/nodes", api.GetNodes)
	http.HandleFunc("/api/timeline", api.GetTimeline)
	http.HandleFunc("/api/stats", api.GetStats)

	// Health check endpoint
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "OK")
	})

	// Start server
	addr := ":8080"
	log.Printf("Starting server on http://localhost%s", addr)
	log.Println("Ready to accept file uploads...")

	server := &http.Server{
		Addr:         addr,
		ReadTimeout:  readTimeoutSec * time.Second,
		WriteTimeout: writeTimeoutSec * time.Second,
		IdleTimeout:  idleTimeoutSec * time.Second,
	}

	err := server.ListenAndServe()
	if err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}
