package wave

import (
	"github.com/VirgilSecurity/virgil-cli/client"
	"github.com/VirgilSecurity/virgil-cli/cmd/wave/dcm"
	"gopkg.in/urfave/cli.v2"
)

func Dcm(client *client.VirgilHttpClient) *cli.Command {
	return &cli.Command{
		Name:  "dcm",
		Usage: "Manage your dcm certificates",
		Subcommands: []*cli.Command{
			dcm.DcmList(client),
			dcm.DsmCreate(client),
		},
	}
}
