package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

func enviarAlertaDiscord(mensaje string) {
	webhookURL := os.Getenv("DISCORD_WEBHOOK_URL")
	if webhookURL == "" {
		return
	}
	payload := map[string]string{"content": "🚨 " + mensaje}
	jsonPayload, _ := json.Marshal(payload)
	// #nosec G107
	resp, err := http.Post(webhookURL, "application/json", bytes.NewBuffer(jsonPayload))
	if err == nil {
		defer resp.Body.Close()
	}
}

func esAtaque(r *http.Request) (bool, string) {
	// Analizamos tanto el Path como la Query String (id=1'OR...)
	analizar := strings.ToUpper(r.URL.RequestURI())

	patrones := map[string]string{
		"../":         "Path Traversal",
		"/ETC/PASSWD": "Archivo Crítico",
		"SELECT":      "SQL Injection",
		"UNION":       "SQL Injection",
		"OR%20":       "SQL Injection",
		"'":           "Caracter sospechoso",
		"<SCRIPT>":    "XSS",
	}

	for patron, desc := range patrones {
		if strings.Contains(analizar, patron) {
			return true, desc
		}
	}
	return false, ""
}

func handler(w http.ResponseWriter, r *http.Request) {
	// 1. Logs de cada petición
	log.Printf("level=info method=%s path=%s remote=%s", r.Method, r.URL.Path, r.RemoteAddr)

	// 2. Health Check (Prioritario para el pipeline)
	if r.URL.Path == "/health" {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "OK")
		return
	}

	// 3. CAPA DE SEGURIDAD (Evita falsos positivos en /)
	if r.URL.Path != "/" && r.URL.Path != "/health" {
		if detectado, motivo := esAtaque(r); detectado {
			log.Printf("level=critical msg='ATAQUE' path=%s motivo=%s", r.URL.Path, motivo)
			enviarAlertaDiscord(fmt.Sprintf("Intento de %s en %s", motivo, r.URL.RequestURI()))
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, "Acceso denegado.")
			return
		}
	}

	// 4. Endpoint de fallo manual
	if r.URL.Path == "/simular-fallo" {
		log.Printf("level=critical msg='Fallo manual'")
		enviarAlertaDiscord("Fallo manual detectado")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// 5. Ruta Principal (HOME) - Solo responde si es exactamente "/"
	if r.URL.Path == "/" {
		// Verificamos si existe el archivo antes para evitar el 404 de ServeFile
		if _, err := os.Stat("static/logo.png"); err == nil {
			http.ServeFile(w, r, "static/logo.png")
		} else {
			fmt.Fprint(w, "Bienvenido al servidor seguro (Imagen no encontrada)")
		}
		return
	}

	// 6. Si nada de lo anterior coincide
	http.NotFound(w, r)
}

func main() {
	f, _ := os.OpenFile("app.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if f != nil {
		log.SetOutput(f)
		defer f.Close()
	}

	// Registramos solo el handler raíz
	http.HandleFunc("/", handler)

	server := &http.Server{
		Addr:         ":8080",
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  15 * time.Second,
	}

	log.Println("Servidor iniciado en 8080")
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}
