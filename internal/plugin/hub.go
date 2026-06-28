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

type PluginInfo struct {
	Name string `json:"Name"`
	Cert string `json:"Cert"`
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

func (h *Hub) GetPlugin(name string) PluginInfo {
	info, err := h.registry.GetPlugin(context.Background(), name)
	if err != nil {
		panic(err)
	}
	if info == nil {
		panic(fmt.Errorf("plugin not found"))
	}
	return *info
}
