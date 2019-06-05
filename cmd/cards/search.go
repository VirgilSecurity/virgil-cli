package cards

import (
	"encoding/base64"
	"fmt"
	"github.com/VirgilSecurity/virgil-cli/utils"
	"gopkg.in/urfave/cli.v2"
	"gopkg.in/virgil.v5/cryptoimpl"
	"gopkg.in/virgil.v5/sdk"
	"io/ioutil"
	"time"
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
			&cli.StringFlag{Name: "c", Usage: "private key password"},
		},
		Usage: "search cards by identity",
		Action: func(context *cli.Context) error {

			identity := utils.ReadParamOrDefaultOrFromConsole(context, "identity", "Enter card identity", "")
			cardVerifier, err := sdk.NewVirgilCardVerifier(cardCrypto, true, true)
			if err != nil {
				return err
			}

			configFileName := utils.ReadFlagOrDefault(context, "c", "")

			data, err := ioutil.ReadFile(configFileName)
			if err != nil {
				return err
			}

			conf, err := utils.ParseAppConfig(data)

			privateKey, err := crypto.ImportPrivateKey(conf.ApiKey, "")
			if err != nil {
				return err
			}

			ttl := time.Minute

			jwtGenerator := sdk.NewJwtGenerator(privateKey, conf.ApiKeyID, tokenSigner, conf.AppID, ttl)

			mgrParams := &sdk.CardManagerParams{
				Crypto:              cardCrypto,
				CardVerifier:        cardVerifier,
				AccessTokenProvider: sdk.NewGeneratorJwtProvider(jwtGenerator, nil, ""),
			}

			cardManager, err := sdk.NewCardManager(mgrParams)

			cards, err := cardManager.SearchCards(identity)

			if err != nil {
				return err
			}

			for _, c := range cards {
				pk, err := crypto.ExportPublicKey(c.PublicKey)
				if err != nil {
					return err
				}
				fmt.Println(c.Id + "      " + base64.StdEncoding.EncodeToString(pk))
			}

			return nil
		},
	}
}

