# Virgil CLI

[Installation](#installation) | [Commands](#commands) | [Using Example](#using-example) | [Support](#support)

[Virgil Security](https://virgilsecurity.com) is a stack of security libraries and all the necessary infrastructure to enable seamless, end-to-end encryption for any application, platform or device. The Command-line interface (CLI) program is a command line tool for utilizing [Virgil Services](https://developer.virgilsecurity.com/docs/java/references). In a few simple steps you can encrypt and decrypt, sign and verify.


For a full overview head over to our [documentation portal](https://developer.virgilsecurity.com/docs/java/references/utilities/cli).

## Installation

The Virgil CLI is provided as a script and an archive of the files, and it is available for Mac and Linux OS.

In order to use the CLI:
1. download the CLI archive or script for you platform [here](/);
2. install the CLI with:
      - MAC OS [install guide](https://developer.virgilsecurity.com/docs/java/references/utilities/cli/settings/install/macos);
      - Linux OS [install guide](https://developer.virgilsecurity.com/docs/java/references/utilities/cli/settings/install/linux).



## Commands

Using the CLI you can:
  * [Generate a Virgil Key](https://developer.virgilsecurity.com/docs/java/references/utilities/cli/commands/generate-key) (Private Key)
  * [Extract a Public Key](https://developer.virgilsecurity.com/docs/java/references/utilities/cli/commands/public-key)
  * [Create](https://developer.virgilsecurity.com/docs/java/references/utilities/cli/commands/create-card) a User's Virgil Card
  * [Get](https://developer.virgilsecurity.com/docs/java/references/utilities/cli/commands/get-card) a User's Virgil Card
  * [Search](https://developer.virgilsecurity.com/docs/java/references/utilities/cli/commands/search-card) for a User's Virgil Card
  * [Revoke](https://developer.virgilsecurity.com/docs/java/references/utilities/cli/commands/revoke-card) a User's Virgil Card
  * [Encrypt data](https://developer.virgilsecurity.com/docs/java/references/utilities/cli/commands/encrypt)
  * [Decrypt](https://developer.virgilsecurity.com/docs/java/references/utilities/cli/commands/decrypt) the encrypted data
  * [Sign data](https://developer.virgilsecurity.com/docs/java/references/utilities/cli/commands/sign)
  * [Verify](https://developer.virgilsecurity.com/docs/java/references/utilities/cli/commands/verify) the signature
  * Some additional commands:
    * Change [Key format](https://developer.virgilsecurity.com/docs/java/references/utilities/cli/commands/additional-commands/key-format)
    * See use's [Card info](https://developer.virgilsecurity.com/docs/java/references/utilities/cli/commands/additional-commands/card-info) (content)
    * Use [Secret Alias](https://developer.virgilsecurity.com/docs/java/references/utilities/cli/commands/additional-commands/secret-alias)

[Learn more about the CLI commands](https://developer.virgilsecurity.com/docs/java/references/utilities/cli) in our documentation.

## Using Example

Virgil Security makes it very easy to sign anything in minutes. With our CLI you need only a few lines of the code and you will get a signed data for every one of your users and devices.

Example: Alice signs some plain.txt:

Alice generates private key (private.virgilkey) with the password (strong_pass)

```bash
virgil keygen -o private.virgilkey -p strong_pass
```
and then Alice signs some 'plain.txt' using her private key

```bash
virgil sign -i plain.txt -o plain.signed -k private.virgilkey -p strong_pass
```

This will result in the creation of a newly signed file (plain.signed).  In this example, the signed file will be stored in the folder, from which the command was run.


[More examples about how to sign data](https://developer.virgilsecurity.com/docs/java/references/utilities/cli/commands/sign)  with the CLI you can find in our documentation.


## License

See [LICENSE](https://github.com/VirgilSecurity/virgil-cli/tree/master/LICENSE) for details.

## Support

Our developer support team is here to help you. You can find us on [Twitter](https://twitter.com/virgilsecurity) and [email](mailto:support@virgilsecurity.com).
