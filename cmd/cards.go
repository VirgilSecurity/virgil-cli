package cmd

import (
	"github.com/VirgilSecurity/virgil-cli/client"
	"github.com/VirgilSecurity/virgil-cli/cmd/cards"
	"gopkg.in/urfave/cli.v2"
)

func Cards(client *client.VirgilHttpClient) *cli.Command {
	return &cli.Command{
		Name:    "cards",
		Usage:   "Manage your cards",
		Subcommands: []*cli.Command{
			cards.Search(),
			cards.Revoke(client),
		},
	}
}

