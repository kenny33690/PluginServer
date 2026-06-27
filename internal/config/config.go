package config

import "os"

type Config struct {
	ListenAddr string
	HubPath    string
	RootCAPath string
	SQLitePath string
}

func Load() Config {
	listenAddr := os.Getenv("LISTEN_ADDR")
	if listenAddr == "" {
		listenAddr = ":29100"
	}

	hubPath := os.Getenv("HUB_PATH")
	if hubPath == "" {
		hubPath = "/ws"
	}

	rootCAPath := os.Getenv("ROOT_CA_PATH")
	if rootCAPath == "" {
		rootCAPath = "root-ca.pem"
	}

	sqlitePath := os.Getenv("SQLITE_PATH")
	if sqlitePath == "" {
		sqlitePath = "pluginserver.db"
	}

	return Config{
		ListenAddr: listenAddr,
		HubPath:    hubPath,
		RootCAPath: rootCAPath,
		SQLitePath: sqlitePath,
	}
}
