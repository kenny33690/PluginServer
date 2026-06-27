package certgen

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type Generator struct {
	Now              func() time.Time
	ConfirmOverwrite func(path string) (bool, error)
}

func New() *Generator {
	return &Generator{Now: time.Now}
}

func (g *Generator) Generate(outDir string) error {
	if outDir == "" {
		outDir = "."
	}

	rootCertPath := filepath.Join(outDir, "root-ca.pem")
	rootKeyPath := filepath.Join(outDir, "root-ca-key.pem")
	serverCertPath := filepath.Join(outDir, "server.pem")
	serverKeyPath := filepath.Join(outDir, "server-key.pem")

	if err := g.confirmOverwrite(rootCertPath, rootKeyPath, serverCertPath, serverKeyPath); err != nil {
		return err
	}

	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate root key: %w", err)
	}

	now := g.Now().UTC()
	rootTemplate, err := certificateTemplate("Root AQ", now, true)
	if err != nil {
		return err
	}
	rootTemplate.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	rootTemplate.BasicConstraintsValid = true
	rootTemplate.MaxPathLen = 1

	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		return fmt.Errorf("create root certificate: %w", err)
	}

	rootCert, err := x509.ParseCertificate(rootDER)
	if err != nil {
		return fmt.Errorf("parse root certificate: %w", err)
	}

	serverKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate server key: %w", err)
	}

	serverTemplate, err := certificateTemplate("Server", now, false)
	if err != nil {
		return err
	}
	serverTemplate.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
	serverTemplate.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	serverTemplate.DNSNames = []string{"localhost"}
	serverTemplate.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}

	serverDER, err := x509.CreateCertificate(rand.Reader, serverTemplate, rootCert, &serverKey.PublicKey, rootKey)
	if err != nil {
		return fmt.Errorf("create server certificate: %w", err)
	}

	if err := writePEM(rootCertPath, "CERTIFICATE", rootDER); err != nil {
		return err
	}
	if err := writeECPrivateKey(rootKeyPath, rootKey); err != nil {
		return err
	}
	if err := writePEM(serverCertPath, "CERTIFICATE", serverDER); err != nil {
		return err
	}
	if err := writeECPrivateKey(serverKeyPath, serverKey); err != nil {
		return err
	}

	return nil
}

func (g *Generator) GeneratePlugin(outDir string, commonName string) (string, string, error) {
	if outDir == "" {
		outDir = "."
	}
	commonName = strings.TrimSpace(commonName)
	if commonName == "" {
		return "", "", fmt.Errorf("plugin common name is required")
	}

	rootCert, err := loadCertificate(filepath.Join(outDir, "root-ca.pem"))
	if err != nil {
		return "", "", err
	}
	rootKey, err := loadECPrivateKey(filepath.Join(outDir, "root-ca-key.pem"))
	if err != nil {
		return "", "", err
	}

	pluginKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("generate plugin key: %w", err)
	}

	now := g.Now().UTC()
	pluginTemplate, err := certificateTemplate(commonName, now, false)
	if err != nil {
		return "", "", err
	}
	pluginTemplate.NotAfter = now.AddDate(5, 0, 0)
	pluginTemplate.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
	pluginTemplate.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}

	pluginDER, err := x509.CreateCertificate(rand.Reader, pluginTemplate, rootCert, &pluginKey.PublicKey, rootKey)
	if err != nil {
		return "", "", fmt.Errorf("create plugin certificate: %w", err)
	}

	certPath := filepath.Join(outDir, commonName+".pem")
	keyPath := filepath.Join(outDir, commonName+"-key.pem")
	if err := g.confirmOverwrite(certPath, keyPath); err != nil {
		return "", "", err
	}

	if err := writePEM(certPath, "CERTIFICATE", pluginDER); err != nil {
		return "", "", err
	}
	if err := writeECPrivateKey(keyPath, pluginKey); err != nil {
		return "", "", err
	}

	return certPath, keyPath, nil
}

func certificateTemplate(commonName string, now time.Time, isCA bool) (*x509.Certificate, error) {
	serialNumber, err := randomSerialNumber()
	if err != nil {
		return nil, fmt.Errorf("generate serial number: %w", err)
	}

	return &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Country:    []string{"AQ"},
			CommonName: commonName,
		},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.AddDate(10, 0, 0),
		SignatureAlgorithm:    x509.ECDSAWithSHA256,
		BasicConstraintsValid: true,
		IsCA:                  isCA,
	}, nil
}

func randomSerialNumber() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, err
	}
	return serialNumber, nil
}

func (g *Generator) confirmOverwrite(paths ...string) error {
	for _, path := range paths {
		if _, err := os.Stat(path); err == nil {
			if g.ConfirmOverwrite == nil {
				return fmt.Errorf("refusing to overwrite existing file: %s", path)
			}
			ok, err := g.ConfirmOverwrite(path)
			if err != nil {
				return err
			}
			if !ok {
				return fmt.Errorf("overwrite cancelled: %s", path)
			}
		} else if !os.IsNotExist(err) {
			return fmt.Errorf("stat %s: %w", path, err)
		}
	}
	return nil
}

func loadCertificate(path string) (*x509.Certificate, error) {
	block, err := readPEMBlock(path)
	if err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse certificate %s: %w", path, err)
	}
	return cert, nil
}

func loadECPrivateKey(path string) (*ecdsa.PrivateKey, error) {
	block, err := readPEMBlock(path)
	if err != nil {
		return nil, err
	}

	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse EC private key %s: %w", path, err)
	}
	return key, nil
}

func readPEMBlock(path string) (*pem.Block, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	block, _ := pem.Decode(content)
	if block == nil {
		return nil, fmt.Errorf("decode %s: invalid PEM data", path)
	}
	return block, nil
}

func writePEM(path string, pemType string, der []byte) error {
	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	defer file.Close()

	if err := pem.Encode(file, &pem.Block{Type: pemType, Bytes: der}); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}

	return nil
}

func writeECPrivateKey(path string, key *ecdsa.PrivateKey) error {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return fmt.Errorf("marshal EC private key: %w", err)
	}

	return writePEM(path, "EC PRIVATE KEY", der)
}
