package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"

	"pluginserver/internal/certgen"
	"pluginserver/internal/logger"
)

func main() {
	outDir := flag.String("out", ".", "output directory")
	flag.Parse()
	args := flag.Args()

	generator := certgen.New()
	generator.ConfirmOverwrite = promptOverwrite

	if len(args) > 0 && args[0] == "plugin" {
		commonName, err := parsePluginCN(args[1:])
		if err != nil {
			logger.Fatalf("%v", err)
		}

		certPath, keyPath, err := generator.GeneratePlugin(*outDir, commonName)
		if err != nil {
			logger.Fatalf("%v", err)
		}

		logger.Infof("generated plugin certificate %s and key %s", certPath, keyPath)
		return
	}

	if err := generator.Generate(*outDir); err != nil {
		logger.Fatalf("%v", err)
	}

	logger.Infof("generated root-ca.pem, root-ca-key.pem, server.pem, server-key.pem in %s", *outDir)
}

func promptOverwrite(path string) (bool, error) {
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Printf("%s already exists. Overwrite? [y/N]: ", path)
		input, err := reader.ReadString('\n')
		if err != nil {
			return false, err
		}

		switch strings.ToLower(strings.TrimSpace(input)) {
		case "y", "yes":
			return true, nil
		case "", "n", "no":
			return false, nil
		}
	}
}

func parsePluginCN(args []string) (string, error) {
	for _, arg := range args {
		if strings.HasPrefix(arg, "CN=") {
			cn := strings.TrimSpace(strings.TrimPrefix(arg, "CN="))
			if cn == "" {
				return "", fmt.Errorf("plugin CN is required")
			}
			return cn, nil
		}
	}

	return "", fmt.Errorf("usage: certman plugin CN=<plugin>")
}
