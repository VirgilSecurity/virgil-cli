package scms

import (
	"github.com/urfave/cli/v2"

	"github.com/VirgilSecurity/virgil-cli/client"
	"github.com/VirgilSecurity/virgil-cli/cmd/scms/device"
)

func Device(client *client.VirgilHTTPClient) *cli.Command {
	return &cli.Command{
		Name:  "devices",
		Usage: "Manage your scms devices",
		Subcommands: []*cli.Command{
			device.List(client),
		},
	}
}
