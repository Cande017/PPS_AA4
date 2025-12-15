package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// Test para verificar que el servidor responde correctamente a la ruta de la imagen (/)
func TestHandlerRootPath(t *testing.T) {
	// 1. Crear una solicitud (Request) de prueba GET a la ruta "/"
	req, err := http.NewRequest("GET", "/", nil)
	if err != nil {
		t.Fatal(err) // Falla si no se puede crear la solicitud
	}

	// 2. Crear un ResponseRecorder (grabador de respuesta)
	// Esto simula la respuesta HTTP que enviaría el servidor
	rr := httptest.NewRecorder()

	// 3. Ejecutar la función handler con la solicitud de prueba
	handler(rr, req)

	// 4. Comprobaciones (Assertions)

	// Verificar el código de estado HTTP
	expectedStatus := http.StatusOK // Esperamos un código 200 OK
	if status := rr.Code; status != expectedStatus {
		t.Errorf("handler devolvió código de estado incorrecto: esperado %v, obtenido %v",
			expectedStatus, status)
	}
}
