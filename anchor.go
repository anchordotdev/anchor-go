package anchor

import (
	"crypto/tls"
	"errors"
	"log"
	"net"
	"net/url"

	"golang.org/x/crypto/acme"

	"github.com/anchordotdev/anchor-go/autocert"
)

type Config struct {
	URL *url.URL
	EAB *acme.ExternalAccountBinding

	ServerNames []string

	mgr *autocert.Manager
}

func Listen(network, laddr string, config *Config) (net.Listener, error) {
	if config.mgr == nil {
		if err := config.setup(); err != nil {
			return nil, err
		}
	}

	if len(config.ServerNames) != 1 {
		panic("TODO")
	}

	helloECDSA := &tls.ClientHelloInfo{
		ServerName:   config.ServerNames[0],
		CipherSuites: []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
	}

	crtECDSA, err := config.mgr.GetCertificate(helloECDSA)
	if err != nil {
		log.Fatal(err)
	}

	helloRSA := &tls.ClientHelloInfo{
		ServerName:   config.ServerNames[0],
		CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256},
	}

	crtRSA, err := config.mgr.GetCertificate(helloRSA)
	if err != nil {
		log.Fatal(err)
	}

	cfgTLS := &tls.Config{
		Certificates: []tls.Certificate{*crtECDSA, *crtRSA},
		ServerName:   config.ServerNames[0],
	}

	return tls.Listen(network, laddr, cfgTLS)
}

func (c *Config) setup() error {
	if c.URL == nil {
		return errors.New("anchor: missing required URL field for Config")
	}

	c.mgr = &autocert.Manager{
		Prompt: func(string) bool { return true },
		Client: &acme.Client{
			DirectoryURL: c.URL.String(),
		},
		ExternalAccountBinding: c.EAB,
	}

	return nil
}
