package main

import (
	"pluginserver/internal/app"
	"pluginserver/internal/logger"
)

func main() {
	if err := app.Run(); err != nil {
		logger.Fatalf("%v", err)
	}
}
