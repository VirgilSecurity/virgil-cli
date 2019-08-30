package wave

import (
	"github.com/VirgilSecurity/virgil-cli/client"
	"github.com/VirgilSecurity/virgil-cli/cmd/wave/device"
	"gopkg.in/urfave/cli.v2"
)

func Device(client *client.VirgilHttpClient) *cli.Command {
	return &cli.Command{
		Name:  "dcm",
		Usage: "Manage your wave devices",
		Subcommands: []*cli.Command{
			device.DeviceList(client),
		},
	}
}
