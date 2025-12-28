package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	intentos404     = make(map[string]int)
	limiteBloqueo   = 5
	peticionesPorIP = make(map[string]int)
	limiteDoS       = 20
)

// Limpiador periódico para que el contador de DoS no sea acumulativo eterno
func limpiarContadores() {
	for {
		time.Sleep(10 * time.Second)
		peticionesPorIP = make(map[string]int)
	}
}

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
	analizar := strings.ToUpper(r.URL.RequestURI())
	patrones := map[string]string{
		"../":         "Path Traversal",
		"/ETC/PASSWD": "Archivo Crítico",
		"SELECT":      "SQL Injection",
		"UNION":       "SQL Injection",
		"OR%20":       "SQL Injection",
		"'":           "Caracter sospechoso",
		"<SCRIPT>":    "XSS",
		".ENV":        "Robo de credenciales",
	}

	for patron, desc := range patrones {
		if strings.Contains(analizar, patron) {
			return true, desc
		}
	}
	return false, ""
}

func handler(w http.ResponseWriter, r *http.Request) {
	// Extraer IP de forma robusta
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		ip = r.RemoteAddr
	}

	// --- 1. DETECCIÓN DE DoS ---
	peticionesPorIP[ip]++
	if peticionesPorIP[ip] > limiteDoS {
		log.Printf("level=critical msg='POSIBLE DoS DETECTADO' ip=%s peticiones=%d", ip, peticionesPorIP[ip])
		enviarAlertaDiscord(fmt.Sprintf("🔥 **ALERTA DoS**: La IP %s ha superado el límite de %d peticiones en 10s.", ip, limiteDoS))
		w.WriteHeader(http.StatusTooManyRequests)
		fmt.Fprint(w, "Demasiadas peticiones. Bloqueado por seguridad.")
		return
	}

	// --- 2. RUTAS PRIORITARIAS ---
	if r.URL.Path == "/health" {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "OK")
		return
	}

	// --- 3. CAPA DE SEGURIDAD (Patrones Maliciosos) ---
	if r.URL.Path != "/" {
		if detectado, motivo := esAtaque(r); detectado {
			log.Printf("level=critical msg='ATAQUE DETECTADO' path=%s motivo=%s ip=%s", r.URL.Path, motivo, ip)
			enviarAlertaDiscord(fmt.Sprintf("⚠️ **ATAQUE DETECTADO**: %s de la IP %s en la ruta %s", motivo, ip, r.URL.RequestURI()))
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, "Acceso denegado: Actividad sospechosa.")
			return
		}
	}

	// --- 4. RUTAS VÁLIDAS ---
	if r.URL.Path == "/" {
		if _, err := os.Stat("static/logo.png"); err == nil {
			http.ServeFile(w, r, "static/logo.png")
		} else {
			fmt.Fprint(w, "Servidor Seguro Activo")
		}
		return
	}

	if r.URL.Path == "/metrics" {
		promhttp.Handler().ServeHTTP(w, r)
		return
	}

	if r.URL.Path == "/simular-fallo" {
		log.Printf("level=critical msg='Fallo manual' ip=%s", ip)
		enviarAlertaDiscord("Simulación de fallo manual activada por " + ip)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// --- 5. DETECCIÓN DE FUERZA BRUTA (404) ---
	intentos404[ip]++
	log.Printf("level=warning msg='404 detectado' ip=%s path=%s intentos=%d", ip, r.URL.Path, intentos404[ip])

	if intentos404[ip] >= limiteBloqueo {
		log.Printf("level=critical msg='ESCANEO DETECTADO' ip=%s", ip)
		enviarAlertaDiscord(fmt.Sprintf("🛡️ **BLOQUEO POR FUERZA BRUTA**: \n- IP Atacante: %s\n- Acción: %d errores 404 acumulados.", ip, intentos404[ip]))
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

	// Lanzar limpiador de DoS en segundo plano
	go limpiarContadores()

	// --- CAPTURA DE SEÑAL PARA ALERTA DE SERVICIO CAÍDO ---
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigs
		log.Printf("level=critical msg='SERVICIO DETENIDO' signal=%v", sig)
		enviarAlertaDiscord("💀 **SERVICIO CAÍDO**: El servidor se ha detenido (Señal: " + sig.String() + ")")
		os.Exit(0)
	}()

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
