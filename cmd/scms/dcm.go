package scms

import (
	"gopkg.in/urfave/cli.v2"

	"github.com/VirgilSecurity/virgil-cli/client"
	"github.com/VirgilSecurity/virgil-cli/cmd/scms/dcm"
)

func Dcm(client *client.VirgilHTTPClient) *cli.Command {
	return &cli.Command{
		Name:  "dcm",
		Usage: "Manage your dcm certificates",
		Subcommands: []*cli.Command{
			dcm.List(client),
			dcm.Create(client),
		},
	}
}
