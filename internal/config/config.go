package config

import "os"

type Config struct {
	ListenAddr string
	WSPath     string
}

func Load() Config {
	listenAddr := os.Getenv("LISTEN_ADDR")
	if listenAddr == "" {
		listenAddr = ":29100"
	}

	return Config{
		ListenAddr: listenAddr,
		WSPath:     "/ws",
	}
}
