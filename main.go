package main

import (
	"log"
	"net/http"
)

func handler(w http.ResponseWriter, r *http.Request) {
	// Implementación de Logs Estructurados (requisito de monitorización)
	log.Printf("level=info method=%s path=%s remote_addr=%s",
		r.Method, r.URL.Path, r.RemoteAddr)

	// Requisito: Si la ruta es /, servimos la imagen estática
	if r.URL.Path == "/" {
		// http.ServeFile sirve el contenido del archivo 'static/logo.png'
		http.ServeFile(w, r, "static/logo.png")
		return
	}
}
