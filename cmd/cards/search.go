package cards

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io/ioutil"
	"time"

	"github.com/urfave/cli/v2"
	"gopkg.in/virgil.v5/cryptoimpl"
	"gopkg.in/virgil.v5/sdk"

	"github.com/VirgilSecurity/virgil-cli/utils"
)

var (
	crypto      = cryptoimpl.NewVirgilCrypto()
	cardCrypto  = cryptoimpl.NewVirgilCardCrypto()
	tokenSigner = cryptoimpl.NewVirgilAccessTokenSigner()
)

func Search() *cli.Command {
	return &cli.Command{
		Name:      "search",
		ArgsUsage: "[identity]",
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "c", Usage: "configuration file"},
		},
		Usage: "search cards by identity",
		Action: func(context *cli.Context) error {
			identity := utils.ReadParamOrDefaultOrFromConsole(context, "identity", "Enter card identity", "")
			cardVerifier, err := sdk.NewVirgilCardVerifier(cardCrypto, true, true)
			if err != nil {
				return err
			}

			configFileName := utils.ReadFlagOrDefault(context, "c", "")
			if configFileName == "" {
				return errors.New("configuration file isn't specified (use -c)")
			}

			data, err := ioutil.ReadFile(configFileName)
			if err != nil {
				return err
			}

			conf, err := utils.ParseAppConfig(data)
			if err != nil {
				return err
			}

			privateKey, err := crypto.ImportPrivateKey(conf.APIKey, "")
			if err != nil {
				return err
			}

			ttl := time.Minute

			jwtGenerator := sdk.NewJwtGenerator(privateKey, conf.APIKeyID, tokenSigner, conf.AppID, ttl)

			mgrParams := &sdk.CardManagerParams{
				Crypto:              cardCrypto,
				CardVerifier:        cardVerifier,
				AccessTokenProvider: sdk.NewGeneratorJwtProvider(jwtGenerator, nil, ""),
			}

			cardManager, err := sdk.NewCardManager(mgrParams)
			if err != nil {
				return err
			}

			cards, err := cardManager.SearchCards(identity)
			if err != nil {
				return err
			}

			if len(cards) == 0 {
				fmt.Println("there are no cards found for identity : " + identity)
				return nil
			}

			fmt.Printf("|%64s |%63s |%20s\n", " Card Id   ", "Public key   ", " created_at ")
			fmt.Printf("|%64s|%64s|%20s\n",
				"-----------------------------------------------------------------",
				"----------------------------------------------------------------",
				"---------------------------------------",
			)
			for _, c := range cards {
				pk, err := crypto.ExportPublicKey(c.PublicKey)
				if err != nil {
					return err
				}
				fmt.Printf("|%63s |%63s |%20s\n", c.Id, base64.StdEncoding.EncodeToString(pk), c.CreatedAt)
			}

			return nil
		},
	}
}
