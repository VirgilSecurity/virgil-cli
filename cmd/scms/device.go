package scms

import (
	"github.com/VirgilSecurity/virgil-cli/client"
	"github.com/VirgilSecurity/virgil-cli/cmd/scms/device"
	"gopkg.in/urfave/cli.v2"
)

func Device(client *client.VirgilHttpClient) *cli.Command {
	return &cli.Command{
		Name:  "devices",
		Usage: "Manage your scms devices",
		Subcommands: []*cli.Command{
			device.DeviceList(client),
		},
	}
}
