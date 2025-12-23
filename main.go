package main

import (
	"log"
	"net/http"
	"time"
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

/*func main() {
	// 1. Le decimos al servidor: "Cuando alguien entre a '/', usa la función 'handler'"
	http.HandleFunc("/", handler)

	// 2. Imprimimos un mensaje para saber que estamos vivos
	log.Println("Iniciando servidor en el puerto 8080...")

	// 3. Encendemos el servidor en el puerto 8080
	// ListenAndServe se queda escuchando eternamente.
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatal(err)
	}
}*/

func main() {
	// 1. Configuración del handler
	http.HandleFunc("/", handler)

	// 2. Configuración SEGURA del servidor (Corrección G114)
	// En lugar de usar http.ListenAndServe directamente, definimos un servidor
	// con tiempos de espera (timeouts) para evitar ataques DoS (Slowloris).
	server := &http.Server{
		Addr:         ":8080",
		Handler:      nil,              // Usa el DefaultServeMux (donde registramos el handler)
		ReadTimeout:  10 * time.Second, // Tiempo máximo para leer la petición
		WriteTimeout: 10 * time.Second, // Tiempo máximo para escribir la respuesta
		IdleTimeout:  15 * time.Second, // Tiempo máximo de espera entre peticiones
	}

	log.Println("Verificando pipeline brrr....")

	// 3. Arrancamos el servidor configurado
	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
