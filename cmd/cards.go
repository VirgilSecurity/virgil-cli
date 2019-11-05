package cmd

import (
	"gopkg.in/urfave/cli.v2"

	"github.com/VirgilSecurity/virgil-cli/client"
	"github.com/VirgilSecurity/virgil-cli/cmd/cards"
)

func Cards(client *client.VirgilHTTPClient) *cli.Command {
	return &cli.Command{
		Name:  "cards",
		Usage: "Manage your cards",
		Subcommands: []*cli.Command{
			cards.Search(),
			cards.Revoke(client),
		},
	}
}
