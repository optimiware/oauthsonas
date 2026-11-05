package server

import (
	"embed"
	"html/template"

	"github.com/optimiweb/oauthsonas/internal/config"
)

//go:embed templates/*.html
var templateFS embed.FS

var templates = template.Must(template.ParseFS(templateFS, "templates/*.html"))

const (
	pickerTemplate = "picker.html"
	gateTemplate   = "gate.html"
)

type pickerData struct {
	Personas      []config.Persona
	CSRF          string
	InteractionID string
}

type gateData struct {
	ReturnTo string
	Error    string
}
