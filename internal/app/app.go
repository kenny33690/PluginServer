package app

import (
	"net/http"

	"pluginserver/internal/config"
	"pluginserver/internal/logger"
	"pluginserver/internal/ws"
)

func Run() error {
	cfg := config.Load()
	ws.SetLogger(logger.Infof)

	mux := http.NewServeMux()
	mux.HandleFunc(cfg.WSPath, ws.Handler)

	logger.Infof("websocket receiver listening on %s%s", cfg.ListenAddr, cfg.WSPath)
	return http.ListenAndServe(cfg.ListenAddr, mux)
}
