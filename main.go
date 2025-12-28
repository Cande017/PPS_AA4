package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"
)

// Función para enviar alertas a Discord usando variables de entorno
func enviarAlertaDiscord(mensaje string) {
	webhookURL := os.Getenv("DISCORD_WEBHOOK_URL")
	if webhookURL == "" {
		log.Println("level=warning msg='Webhook de Discord no configurado'")
		return
	}

	payload := map[string]string{
		"content": "🚨 **ALERTA DEVSECOPS**: " + mensaje,
	}
	jsonPayload, _ := json.Marshal(payload)

	// #nosec G107 - La URL proviene de una variable de entorno segura configurada en Secrets
	resp, err := http.Post(webhookURL, "application/json", bytes.NewBuffer(jsonPayload))
	if err != nil {
		log.Printf("Error enviando alerta: %v", err)
		return
	}
	defer resp.Body.Close()
}

func handler(w http.ResponseWriter, r *http.Request) {
	// Endpoint de simulación de fallo (Evento Anómalo)
	if r.URL.Path == "/simular-fallo" {
		log.Printf("level=critical msg='Evento anómalo detectado' method=%s path=%s remote=%s", r.Method, r.URL.Path, r.RemoteAddr)
		enviarAlertaDiscord("Acceso detectado al endpoint de fallo desde " + r.RemoteAddr)

		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, "Error 500: Fallo detectado y alerta enviada.")
		return
	}

	// Logs Estructurados para rutas normales
	log.Printf("level=info method=%s path=%s remote_addr=%s", r.Method, r.URL.Path, r.RemoteAddr)

	if r.URL.Path == "/" {
		http.ServeFile(w, r, "static/logo.png")
		return
	}

	// 404
	log.Printf("level=warning msg='Ruta no encontrada' path=%s", r.URL.Path)
	http.NotFound(w, r)
}

func main() {
	// Configuración de logs en archivo con permisos seguros (G302 corregido)
	f, err := os.OpenFile("app.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err == nil {
		log.SetOutput(f)
		defer f.Close()
	}
	// 1. Configuración del handler
	http.HandleFunc("/", handler)
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "OK")
	})

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

	log.Println("Iniciando servidor por puerto 8080")

	// Control de error al arrancar (G104 corregido)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Error crítico: %v", err)
	}
}
