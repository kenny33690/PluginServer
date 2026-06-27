package app

import (
	"context"
	"net/http"

	"pluginserver/internal/config"
	"pluginserver/internal/logger"
	"pluginserver/internal/plugin"

	"github.com/philippseith/signalr"
)

func Run() error {
	cfg := config.Load()
	validator, err := plugin.NewValidator(cfg.RootCAPath)
	if err != nil {
		return err
	}

	registry, err := plugin.OpenRegistry(context.Background(), cfg.SQLitePath)
	if err != nil {
		return err
	}
	defer registry.Close()

	server, err := signalr.NewServer(
		context.Background(),
		signalr.SimpleHubFactory(plugin.NewHub(validator, registry)),
	)
	if err != nil {
		return err
	}

	mux := http.NewServeMux()
	server.MapHTTP(signalr.WithHTTPServeMux(mux), cfg.HubPath)

	logger.Infof("signalr server listening on %s%s", cfg.ListenAddr, cfg.HubPath)
	return http.ListenAndServe(cfg.ListenAddr, mux)
}
