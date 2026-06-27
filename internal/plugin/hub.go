package plugin

import (
	"context"
	"fmt"
	"strings"

	"github.com/philippseith/signalr"
)

type Hub struct {
	signalr.Hub
	validator *Validator
	registry  *Registry
}

func NewHub(validator *Validator, registry *Registry) *Hub {
	return &Hub{
		validator: validator,
		registry:  registry,
	}
}

func (h *Hub) CreatePlugin(name string, certString string) (string, error) {
	name = strings.TrimSpace(name)
	certString = strings.TrimSpace(certString)

	if name == "" {
		return "", fmt.Errorf("name is required")
	}
	if certString == "" {
		return "", fmt.Errorf("cert-string is required")
	}

	certInfo, err := h.validator.ValidatePluginCert(name, certString)
	if err != nil {
		return "", err
	}

	if err := h.registry.SavePlugin(context.Background(), name, certString, certInfo.Subject, certInfo.NotBefore, certInfo.NotAfter); err != nil {
		return "", err
	}

	return "plugin created", nil
}
