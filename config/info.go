package config

import (
	"fmt"
	"os"
)

type Info struct {
	// Port is the local port on which the application will run
	Port string

	// FQDN (for Fully-Qualified Domain Name) is the internet facing host address
	// where application will live (e.g. https://example.com)
	FQDN string

	// ClientID comes from your configured GitHub app
	ClientID string

	// ClientSecret comes from your configured GitHub app
	ClientSecret string
}

const (
	portEnv         = "PORT"
	clientIdEnv     = "CLIENT_ID"
	clientSecretEnv = "CLIENT_SECRET"
	fqdnEnv         = "FQDN"
)

func New() (*Info, error) {
	port := os.Getenv(portEnv)
	if port == "" {
		return nil, fmt.Errorf("%s environment variable required", portEnv)
	}
	fmt.Println("PORT:", port)

	fqdn := os.Getenv(fqdnEnv)
	if fqdn == "" {
		return nil, fmt.Errorf("%s environment variable required", fqdnEnv)
	}
	fmt.Println("FQDN:", fqdn)

	clientID := os.Getenv(clientIdEnv)
	if clientID == "" {
		return nil, fmt.Errorf("%s environment variable required", clientIdEnv)
	}
	fmt.Println("CLIENT_ID:", clientID)

	clientSecret := os.Getenv(clientSecretEnv)
	if clientSecret == "" {
		return nil, fmt.Errorf("%s environment variable required", clientSecretEnv)
	}
	fmt.Println("CLIENT_SECRET:", clientSecret)

	return &Info{
		Port:         port,
		FQDN:         fqdn,
		ClientID:     clientID,
		ClientSecret: clientSecret,
	}, nil
}
