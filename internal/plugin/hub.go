package plugin

import (
	"context"
	"fmt"
	"pluginserver/internal/logger"
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

func (h *Hub) CreatePlugin(name string, certString string) string {
	name = strings.TrimSpace(name)
	logger.Infof("name:%s", name)
	certString = strings.TrimSpace(certString)

	if name == "" {
		panic(fmt.Errorf("name is required"))
	}
	if certString == "" {
		panic(fmt.Errorf("cert-string is required"))
	}

	certInfo, err := h.validator.ValidatePluginCert(name, certString)
	if err != nil {
		panic(err)
	}

	if err := h.registry.SavePlugin(context.Background(), name, certString, certInfo.Subject, certInfo.NotBefore, certInfo.NotAfter); err != nil {
		panic(err)
	}
	return "plugin created"
}
