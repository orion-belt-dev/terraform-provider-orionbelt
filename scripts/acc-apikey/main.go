// Command acc-apikey prints an API key for the acceptance tests by signing
// in to a gateway with the admin's SSH key.
//
//	go run ./scripts/acc-apikey http://localhost:8080 ~/Projects/orion-belt/admin-key
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/orion-belt-dev/orion-belt/pkg/sdk"
	"golang.org/x/crypto/ssh"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: acc-apikey <gateway-url> <admin-private-key>")
		os.Exit(2)
	}
	if err := run(os.Args[1], os.Args[2]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(url, keyPath string) error {
	pem, err := os.ReadFile(keyPath) //nolint:gosec // the operator names the key file on the command line
	if err != nil {
		return err
	}
	signer, err := ssh.ParsePrivateKey(pem)
	if err != nil {
		return err
	}
	client, err := sdk.NewClient(url)
	if err != nil {
		return err
	}
	res, err := client.LoginWithSSHKey(context.Background(), "admin", signer, "")
	if err != nil {
		return err
	}
	fmt.Print(res.APIKey)
	return nil
}
