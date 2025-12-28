package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

func esAtaque(rawURL string) (bool, string) {
	// 1. Decodificamos la URL (convierte %27 en ', %20 en espacio, etc.)
	decodedURL, err := url.PathUnescape(rawURL)
	if err != nil {
		decodedURL = rawURL // Si falla, usamos la original
	}

	pathUpper := strings.ToUpper(decodedURL)

	patrones := map[string]string{
		"../":         "Path Traversal",
		"/ETC/PASSWD": "Lectura de archivos críticos",
		"SELECT":      "Inyección SQL",
		"UNION":       "Inyección SQL",
		"OR '1'='1'":  "Inyección SQL (bypass)",
		"OR 1=1":      "Inyección SQL (bypass)",
		"<SCRIPT>":    "XSS",
		".ENV":        "Robo de credenciales",
	}

	for patron, descripcion := range patrones {
		if strings.Contains(pathUpper, patron) {
			return true, descripcion
		}
	}
	return false, ""
}

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
	// --- CAPA DE SEGURIDAD ---
	urlParaAnalizar := r.URL.RequestURI() // RequestURI incluye path y query
	detectado, motivo := esAtaque(urlParaAnalizar)

	if detectado {
		log.Printf("level=critical msg='ATAQUE' url=%s motivo=%s", urlParaAnalizar, motivo)
		enviarAlertaDiscord(fmt.Sprintf("ATAQUE: %s en %s", motivo, urlParaAnalizar))
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, "Acceso denegado.")
		return
	}

	// --- RUTAS DE LA APLICACIÓN (Corregido) ---
	// Usamos un switch o ifs claros para no pisar el 404

	if r.URL.Path == "/" {
		log.Printf("level=info path=/")
		// Asegúrate de que la carpeta static/logo.png existe
		http.ServeFile(w, r, "static/logo.png")
		return
	}

	if r.URL.Path == "/health" {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "OK")
		return
	}

	if r.URL.Path == "/simular-fallo" {
		log.Printf("level=critical msg='Fallo manual'")
		enviarAlertaDiscord("Simulación de fallo manual")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Si no es ninguna de las anteriores, entonces sí es 404
	log.Printf("level=warning msg='404' path=%s", r.URL.Path)
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
