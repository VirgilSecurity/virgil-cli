# Virgil CLI
[![Build Status](https://travis-ci.org/VirgilSecurity/virgil-cli.png?branch=v5)](https://travis-ci.org/VirgilSecurity/virgil-cli)
[![GitHub license](https://img.shields.io/badge/license-BSD%203--Clause-blue.svg)](https://github.com/VirgilSecurity/virgil/blob/master/LICENSE)


<a href="https://developer.virgilsecurity.com/docs"><img width="230px" src="https://cdn.virgilsecurity.com/assets/images/github/logos/virgil-logo-red.png" align="left" hspace="10" vspace="6"></a> [Virgil Security](https://virgilsecurity.com) introduces to developers a **Virgil CLI** – a tool that provides commands for interacting with the Virgil Security services. With minimal configuration, you can start using all of the functionality provided by the Virgil from your favorite terminal program.
- **Linux shells** – Use common shell programs such as Bash, Zsh, and tsch to run commands in Linux, macOS, or Unix.
- **Windows command line** – On Microsoft Windows, run commands in either PowerShell or the Windows Command Processor.


## Content
- [Installation](#installation)
- [Launching CLI](#launching-cli)
- [Features](#features)
- [Commands usage](#commands-usage)
  - [Update keys](#update-keys)
  - [Generate a secret key](#generate-a-secret-key)
- [License](#license)
- [Support](#support)

## Features
Using the Virgil CLI you can:
  * get your Virgil PURE application credentials, such as: Application Token, Application Secret Key
  * update your Virgil PURE application credentials

To get more information, run the Virgil CLI or its command with the `--help` or `-h` option that displays full help list and available commands.

## Installation
The Virgil CLI is provided as a binary file, and it is available for Mac OS, FreeBSD,  Linux OS and Windows OS. Download the latest CLI package here: https://github.com/VirgilSecurity/virgil-cli/releases.


## Launching Virgil CLI

#### FreeBSD / Linux / Mac OS
Run the CLI with the following command:
```bash
./virgil
```
> or use `sudo ./virgil` when you need to run the command as an administrator

#### Windows OS
Run the CLI with the following command:
```bash
virgil.exe
# or just `virgil`
```

### Update keys
This command is used to update the `app_secret_key` and `service_public_key` of a specific application

```bash
# FreeBSD / Linux / Mac OS
./virgil pure update-keys <service_public_key> <app_secret_key> <update_token>

# Windows OS
virgil pure update-keys <service_public_key> <app_secret_key> <update_token>
```

### Generate a secret key
This command is used to generate a new `app_secret_key`:
```bash
# FreeBSD / Linux / Mac OS
./virgil pure keygen

# Windows OS
virgil pure keygen
```


## License
See [LICENSE](https://github.com/VirgilSecurity/virgil-cli/tree/master/LICENSE) for details.

## Support
Our developer support team is here to help you. Find out more information on our [Help Center](https://help.virgilsecurity.com/).

You can find us on [Twitter](https://twitter.com/VirgilSecurity) or send us email support@VirgilSecurity.com.

Also, get extra help from our support team on [Slack](https://virgilsecurity.com/join-community).
