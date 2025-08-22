package handlers

import (
	"embed"
	"io/fs"
	"log"
	"net/http"
)

// StaticHandler serves static files from the embedded filesystem..
func StaticHandler(staticFS embed.FS) http.Handler {
	staticSubFS, err := fs.Sub(staticFS, "static")
	if err != nil {
		panic(err)
	}

	return http.FileServer(http.FS(staticSubFS))
}

// IndexHandler serves the main index.html file from embedded filesystem..
func IndexHandler(staticFS embed.FS) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Read index.html from embedded filesystem
		data, err := staticFS.ReadFile("static/index.html")
		if err != nil {
			http.Error(w, "Index file not found", http.StatusNotFound)

			return
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, err = w.Write(data)
		if err != nil {
			log.Printf("Error writing response: %v", err)
		}
	}
}
