package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

var (
	intentos404 = make(map[string]int)
	// Definimos el límite: 5 errores 404 y saltará la alerta
	limiteBloqueo = 5
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
	// 1. Logs de cada petición (Para auditoría)
	log.Printf("level=info method=%s path=%s remote=%s", r.Method, r.URL.Path, r.RemoteAddr)

	// 2. Health Check (Exento de seguridad para evitar falsos positivos del pipeline)
	if r.URL.Path == "/health" {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "OK")
		return
	}

	// 3. CAPA DE SEGURIDAD GLOBAL
	// Analizamos todo lo que no sea la raíz "/"
	if r.URL.Path != "/" {
		if detectado, motivo := esAtaque(r); detectado {
			log.Printf("level=critical msg='ATAQUE DETECTADO' path=%s motivo=%s", r.URL.Path, motivo)
			enviarAlertaDiscord(fmt.Sprintf("⚠️ **ATAQUE DETECTADO**: %s en la ruta %s", motivo, r.URL.RequestURI()))

			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, "Acceso denegado: Actividad sospechosa.")
			return
		}
	}

	// 4. Lógica de rutas normales
	if r.URL.Path == "/" {
		// Intentamos servir el logo
		if _, err := os.Stat("static/logo.png"); err == nil {
			http.ServeFile(w, r, "static/logo.png")
		} else {
			fmt.Fprint(w, "Servidor Seguro Activo")
		}
		return
	}

	if r.URL.Path == "/simular-fallo" {
		log.Printf("level=critical msg='Fallo manual'")
		enviarAlertaDiscord("Simulación de fallo manual activada")
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// --- 2. DETECCIÓN DE FUERZA BRUTA (Aquí cae todo lo que no existe) ---

	// Forma robusta de sacar la IP sin el puerto
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		ip = r.RemoteAddr // Si falla (raro), usamos el original
	}

	intentos404[ip]++

	log.Printf("level=warning msg='404 detectado' ip=%s path=%s intentos=%d",
		ip, r.URL.Path, intentos404[ip])

	if intentos404[ip] >= limiteBloqueo {
		log.Printf("level=critical msg='POSIBLE ESCANEO DETECTADO' ip=%s", ip)

		enviarAlertaDiscord(fmt.Sprintf("🛡️ **BLOQUEO POR FUERZA BRUTA**: \n- IP Atacante: %s\n- Acción: La IP ha generado %d errores 404 intentando adivinar rutas.",
			ip, intentos404[ip]))

		// Opcional: Resetear el contador después de avisar para no inundar Discord
		intentos404[ip] = 0
	}

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
