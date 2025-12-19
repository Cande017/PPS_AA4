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

func main() {
	// 1. Le decimos al servidor: "Cuando alguien entre a '/', usa la función 'handler'"
	http.HandleFunc("/", handler)

	// 2. Imprimimos un mensaje para saber que estamos vivos
	log.Println("Iniciando servidor en el puerto 8080...")

	// 3. Encendemos el servidor en el puerto 8080
	// ListenAndServe se queda escuchando eternamente.
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatal(err)
	}
}
