# Virgil CLI
[![Build Status](https://travis-ci.org/VirgilSecurity/virgil-cli.png?branch=v5)](https://travis-ci.org/VirgilSecurity/virgil-cli)
[![GitHub license](https://img.shields.io/badge/license-BSD%203--Clause-blue.svg)](https://github.com/VirgilSecurity/virgil/blob/master/LICENSE)


<a href="https://developer.virgilsecurity.com/docs"><img width="230px" src="https://cdn.virgilsecurity.com/assets/images/github/logos/virgil-logo-red.png" align="left" hspace="10" vspace="6"></a> [Virgil Security](https://virgilsecurity.com) introduces to developers a **Virgil CLI** – a tool to manage your Virgil account and applications.                                                                                                                                                                                                                                       With minimal configuration, you can start using all of the functionality provided by the Virgil from your favorite terminal program.
- **Linux shells** – Use common shell programs such as Bash, Zsh, and tsch to run commands in Linux, macOS, or Unix.
- **Windows command line** – On Microsoft Windows, run commands in either PowerShell or the Windows Command Processor.


## Content
- [Installation](#installation)
- [Launching CLI](#launching-cli)
- [Manage Virgil Account](#manage-virgil-account)
  - [Register new Account](#register-new-account)
  - [Login into Account](#login-into-account)
  - [Logout from Account](#logout-from-acccount)
- [Manage Applications](#manage-applications)
  - [Create new application](#create-new-application)
  - [Delete application](#delete-application)
  - [Get list of applications](#list-applications)
  - [Update application](#update-application)
  - [Set up default Application](#use-application)
  - [Create new App Key](#create-new-app-key)
  - [Delete App Key](#delete-app-key)
  - [Get list of App Keys](#list-app-keys)
  - [Update App Key](#update-app-key)
  - [Create App Token](#create-app-token)
  - [Delete App Token](#delete-app-token)
  - [Get list of App Tokens](#list-app-tokens)
- [PureKit Commands](#purekit-commands)
  - [Update keys](#update-keys)
  - [Generate a Secret Key](#generate-a-secret-key)
  - [Generate an Auth Key](#generate-an-auth-key)
  - [Generate a Backup Keypair](#generate-a-backup-keypair)
  - [Generate a Hashes Keypair](#generate-a-hashes-keypair)
  - [Generate a Virgil Storage Key](#generate-a-virgil-storage-key)
  - [Generate Own Signing Key](#generate-own-signing-key)
  - [Generate all Pure keys at once](#generate-all-pure-keys-at-once)
- [Manage Application Cards](#manage-application-cards)
  - [Config file](#config-file)
  - [Search cards](#search-cards)
  - [Revoke card](#revoke-card)
- [Cryptographic Operations](#cryptographic-operations)
  - [Generate private key](#generate-private-key)
  - [Extract public key](#extract-public-key)
  - [Encrypt](#encrypt)
  - [Decrypt](#decrypt)
  - [Sign](#sign)
  - [Verify signature](#verify-signature)
- [SCMS Commands](#scms-commands)
  - [Init SCMS module in application](#init-scms-module-in-application)
  - [Create DCM certificate](#create-dcm-certificate)
  - [Get DCM certificates list](#get-dcm-certificates-list)
  - [Get SCMS devices](#get-scms-devices)
- [License](#license)
- [Support](#support)


## Installation

### Mac OS

#### Install using Homebrew

You can install the Virgil CLI with [Homebrew](http://brew.sh/) using the following command:

```bash
$ brew update
$ brew install virgil
```

#### Install using the package

Download the latest CLI package here: https://github.com/VirgilSecurity/virgil-cli/releases.

Once you've downloaded the latest `.tar.gz` Virgil CLI file, double click to unzip it. Rename the unzipped folder to `virgil_<latest-version>` (`virgil_5.0.3` for example) and move it to any folder of your choice. 

Launch Terminal and type the following command:

```shell
ln -s ~/<full-path-to-virgil-file> /usr/local/bin/virgil
```

Now you will be able to launch the Virgil CLI using Terminal.

### Linux

In order to download and install the CLI using Linux, use the following commands:

```bash
# navigate to the folder which you want to download the archive to
cd <folder-name>

# download the latest version of the Virgil CLI using its link from the releases page https://github.com/VirgilSecurity/virgil-cli/releases
wget https://github.com/VirgilSecurity/virgil-cli/releases/download/v<latest-version>/virgil_<latest-version>_Linux_x86_64.tar.gz

# unzip the downloaded archive specifying its name
tar xvfz <downloaded-file>

# move cli to /usr/local/bin
mv virgil /usr/local/bin
```

Now you will be able to launch the Virgil CLI.

### Windows

Download the latest CLI package here: https://github.com/VirgilSecurity/virgil-cli/releases.

Once you've downloaded the latest `.zip` Virgil CLI file, unzip it and rename the unzipped folder to `virgil_<latest-version>` (`virgil_5.0.3` for example). Move the renamed folder to `C:\ProgramFiles` and copy the full path to the folder.

Edit the system environmental variables:
1. In `Search`, search for and then select: `System` (`Control Panel`)
2. Click the `Advanced system settings` link.
3. Click `Environment Variables`. In the section `System Variables`, find the `PATH` environment variable and select it. Click Edit. If the PATH environment variable does not exist, click New.
4. In the `Edit System Variable` (or `New System Variable`) window, specify the value of the PATH environment variable (paste the copied full path to Virgil CLI folder). Click OK. Close all remaining windows by clicking OK.

Now you will be able to launch Virgil CLI using Command prompt.


## Launching Virgil CLI

Run the CLI with the following command:
```bash
virgil.exe
# or just `virgil`
```

To get more information, run the Virgil CLI or its command with the `--help` or `-h` option that displays full help list and available commands.


## Manage Virgil Account

### Register new account
This command is used to create a new account:
```bash
$ virgil register <email>
```

### Login into account
This command is used to open session for account:
```bash
$ virgil login
```

### Logout from account
This command is used to close the current session for account:
```bash
$ virgil logout
```

## Manage Applications

### Create new application
This command is used to create new application:
```bash
$ virgil app create <app_name>
```
> Note! You have to verify your email in order to be able to create more than one application

### Delete application
This command is used to delete application:
```bash
$ virgil app delete <app_id>
```

### List applications
This command is used to print list of all user applications:
```bash
$ virgil app list
```

### Update application
This command is used to update name of application:
```bash
$ virgil app update <app_id>
```

### Use application
This command allows you to specify the application that will be used by default. In this way, you'll be able you to use CLI commands without specifying `app_id` where it's needed. 

```bash
$ virgil use <app_name>
```

### Create new App Key
This command is used to create new App Key for current application:
```bash
$ virgil app key create --app_id <app_id> <app-key_name>
```

### Delete App Key
This command is used to delete App Key:
```bash
$ virgil app key delete --app_id <app_id> <app-key_id>
```

### List App Keys
This command is used to print list of App Keys of the specified application:
```bash
$ virgil app key list --app_id <app_id> 
```

### Update App Key
This command is used to update name of App Key:
```bash
$ virgil app key update --app_id <app_id> <app-key_id>
```

### Create App Token
This command is used to create an App Token:
```bash
$ virgil app token create --app-id <app-id> --name <name>
```

### Delete App Token
This command is used to delete an App Token:
```bash
$ virgil app token delete --app-id <app-id> <name>
```

### List App Tokens
This command is used to get App Tokens list:
```bash
$ virgil app token list --app-id <app-id>
```

## PureKit Commands

### Update keys
This command is used to update the `App Secret Key` and `Service Public Key` of a Pure application

```bash
$ virgil pure update-keys <public_key> <service_secret_key> <update_token>
```

### Generate a Secret Key
This command is used to generate a new `App Secret Key` for a Pure application:
```bash
$ virgil pure keygen secret
```

### Generate an Auth Key
This command is used to generate a new `Auth Key` for a Pure application:
```bash
$ virgil pure keygen auth
```

### Generate a Backup Keypair
This command is used to generate a `Backup keypair` for a Pure application:
```bash
$ virgil pure keygen backup
```

### Generate a Hashes Keypair
This command is used to generate a `Hashes keypair` for a Pure application:
```bash
$ virgil pure keygen hashes
```

### Generate a Virgil Storage Keypair
This command is used to generate a `Virgil Storage key` for a Pure application:
```bash
$ virgil pure keygen signing
```

### Generate Own Signing Key
This command is used to generate `Own Signing Key` for a Pure application:
```bash
$ virgil pure keygen own
```

### Generate all Pure keys at once
This command is used to generate all Pure keys at once for a Pure application:
```bash
$ virgil pure keygen all
```

## Manage Application Cards

### Config file

Config file is a json, with contains APP_KEY, APP_KEY_ID, APP_ID

It could be generated on dashboard or by hands

config file example : 
```$xslt
{
  "APP_KEY": "1234567890",
  "APP_KEY_ID": "12345678901234567890",
  "APP_ID": "12345678901234567890"
}
```

### Search cards
This command searches for any Virgil Card by its identity:
```bash
$ virgil cards search -c <file> <identity>,
```
```
flags :
-c  - Config file name.
```

### Revoke card
This command deletes Virgil Card by it's id
```bash
$ virgil cards delete -c <file> -i <identity> <card_id>,
```
```
flags :
-c  - Config file name.
-i  - Card identity, mandatory.
```



## Cryptographic operations

### Generate private key
This command generates a User's Private Key:
```bash
$ virgil keygen -o <file> -p <password>,
```
```
flags :
-o  - Key file name. If omitted, stdout is used.
-p  - Use password to encrypt Private Key. If omitted (not recommended), private key will be generated without password
```

### Extract public key
This command extracts a Public Key from a Private Key:
```bash
$ virgil key2pub  -i <file> -o <file> -p <password>,
```
```
flags :
-i  - Key's File Name. If omitted, stdin is used.
-o  - Public key's file name. If omitted, stdout is used.
-p  - Use password to decrypt Private Key. 
```

### Encrypt
This command encrypts any data for the specified public key(s):
```bash
$ virgil encrypt  -i <file> -o <file> -key <public_key_file_1> -key <public_key_file_2> ...,
```

```
flags :
-i  - Data to be encrypted - If omitted, stdin is used..
-o  - Encrypted data. If omitted, stdout is used..
-key  - Public key file (could be many files). 
```

### Decrypt
This command decrypts the encrypted data with a a Private Key:
```bash
$ virgil decrypt  -i <file> -o <file> -key <private_key_file>  -p <password>,
```
```
flags :
-i  - Data to be decrypted - If omitted, stdin is used.
-o  - Decrypted data. If omitted, stdout is used.
-key  - Private key file. 
-p  - Use password to decrypt Private Key. 
```

### Sign
This command signs data with a provided User’s Private Key:
```bash
$ virgil sign  -i <file> -o <file> -key <private_key_file>  -p <password>,
```
```
flags :
-i  - Data to be signed - If omitted, stdin is used.
-o  - The signed data. If omitted, stdout is used.
-key  - Private key file. 
-p  - Use password to decrypt Private Key. 
```


### Verify signature
This command signs data with a provided User’s Private Key:
```bash
$ virgil verify  -i <file> -s <file> -key <public_key_file> ,
```
```
flags :
-i  - File with data which necessary to verify.
-s  - Digest sign.
-key  - Public key file.  If omitted, stdin is used. 
```

## SCMS Commands

### Init SCMS module in application

This command inits SCMS services for application:

```bash
$ virgil scms init --app-id <app-id> 
```

### Create DCM certificate

Generates DCM certificate for application:

```bash
$ virgil scms dcm create --name <dcm_name> --encrypt-pub-key <base64_key> --verify-pub-key <base64_key> --app-token <app_token> 
```

### Get DCM certificates list

Gets DCM certificates for application:

```bash
$ virgil scms dcm list --app-token <app_token> 
```

### Get SCMS devices

Gets list of SCMS devices:

```bash
$ virgil scms devices list --app-token <app_token> 
```


## License
See [LICENSE](https://github.com/VirgilSecurity/virgil-cli/tree/master/LICENSE) for details.

## Support
Our developer support team is here to help you. Find out more information on our [Help Center](https://help.virgilsecurity.com/).

You can find us on [Twitter](https://twitter.com/VirgilSecurity) or send us email support@VirgilSecurity.com.

Also, get extra help from our support team on [Slack](https://virgilsecurity.com/join-community).
