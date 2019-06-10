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
- [Manage PURE application](#manage-pure-application)
  - [Update keys](#update-keys)
  - [Generate a secret key](#generate-a-secret-key)
- [Manage E2EE application](#manage-pure-application)
  - [Create new application](#create-new-e2ee-application)
  - [Delete application](#delete-application)
  - [Get list of E2EE applications](#list-applications)
  - [Update application](#update-application)
  - [Set up default Application](#use-application)
  - [Create new API Key](#create-new-api-key)
  - [Delete API Key](#delete-api-key)
  - [Get list of API Keys](#list-api-key)
  - [Update API Key](#update-api-key)
- [Manage application cards](#manage-application-cards)
  - [Get cards list](#get-cards-list)
  - [Delete card](#delete-card)
- [Cryptographic operations](#cryptographic-operations)
  - [Generate private key](#generate-private-key)
  - [Extract public key](#extract-public-key)
  - [Encrypt](#encrypt)
  - [Decrypt](#decrypt)
  - [Sign](#sign)
  - [Verify signature](#verify-signature)
- [License](#license)
- [Support](#support)


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

To get more information, run the Virgil CLI or its command with the `--help` or `-h` option that displays full help list and available commands.


## Manage Virgil Account

### Register new account
This command is used to create a new account:
```bash
# FreeBSD / Linux / Mac OS
./virgil register <email>

# Windows OS
virgil register <email>
```

### Login into account
This command is used to open session for account:
```bash
# FreeBSD / Linux / Mac OS
./virgil login

# Windows OS
virgil login
```

### Logout from account
This command is used to close the current session for account:
```bash
# FreeBSD / Linux / Mac OS
./virgil logout

# Windows OS
virgil logout
```

## Manage PURE application

### Update keys
This command is used to update the `app_secret_key` and `service_public_key` of a Pure application

```bash
# FreeBSD / Linux / Mac OS
./virgil pure update-keys <service_public_key> <app_secret_key> <update_token>

# Windows OS
virgil pure update-keys <service_public_key> <app_secret_key> <update_token>
```

### Generate a secret key
This command is used to generate a new `app_secret_key` for a Pure application:
```bash
# FreeBSD / Linux / Mac OS
./virgil pure keygen

# Windows OS
virgil pure keygen
```


## Manage E2EE application

### Create new E2EE application
This command is used to create new application:
```bash
# FreeBSD / Linux / Mac OS
./virgil app create --type e2ee <application name>

# Windows OS
virgil app create --type e2ee <application name>
```
> Note! You have to verify your email in order to be able to create more than one application

### Delete application
This command is used to delete application:
```bash
# FreeBSD / Linux / Mac OS
./virgil app delete <application_id>

# Windows OS
virgil app delete <application_id>
```

### List applications
This command is used to print list of all user applications:
```bash
# FreeBSD / Linux / Mac OS
./virgil app list

# Windows OS
virgil app list
```


### Update application
This command is used to update name of application:
```bash
# FreeBSD / Linux / Mac OS
./virgil app update <application_id>

# Windows OS
virgil app update <application_id>
```

### Use application
This command allows you to specify the application that will be used by default. In this way, you'll be able you to use CLI commands without specifying `app_id` where it's needed. 

```bash
# FreeBSD / Linux / Mac OS
./virgil use <app_name>

# Windows OS
virgil use <app_name>
```


### Create new api-key
This command is used to create new api-key for current application:
```bash
# FreeBSD / Linux / Mac OS
./virgil apikey create --app_id <app_id> <api-key name>

# Windows OS
virgil apikey create --app_id <app_id> <api-key name>
```


### Delete api-key
This command is used to delete api-key:
```bash
# FreeBSD / Linux / Mac OS
./virgil apikey delete <api_key_id>

# Windows OS
virgil apikey delete <api_key_id>
```

### List api-keys
This command is used to print list of all users api-keys:
```bash
# FreeBSD / Linux / Mac OS
./virgil apikey list

# Windows OS
virgil apikey list
```


### Update api-key
This command is used to update name of api-key:
```bash
# FreeBSD / Linux / Mac OS
./virgil apikey update <api_key_id>

# Windows OS
virgil apikey update <api_key_id>
```

## Manage application cards

### Get cards list
This command searches for any Virgil Card by its identity:
```bash
# FreeBSD / Linux / Mac OS
./virgil cards search -c <file> identity,

# Windows OS
virgil keygen cards search -c <file> identity,
```
```
flags :
-c  - Config file name.
```

### Delete card
This command deletes Virgil Card by it's id
```bash
# FreeBSD / Linux / Mac OS
./virgil cards delete -c <file> -i identity [card_id],

# Windows OS
virgil cards delete -c <file> -i identity [card_id],
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
# FreeBSD / Linux / Mac OS
./virgil keygen -o <file>  -p password,

# Windows OS
virgil keygen -o <file> -p password,
```
```
flags :
-o  - Key file name. If omitted, stdout is used.
-p  - Use password to encrypt Private Key. If omitted (not recommended), private key will be generated without password
```

### Extract public key
This command extracts a Public Key from a Private Key:
```bash
# FreeBSD / Linux / Mac OS
./virgil key2pub -i <file> -o <file>  -p password,

# Windows OS
virgil key2pub  -i <file> -o <file> -p password,
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
# FreeBSD / Linux / Mac OS
./virgil encrypt  -i <file> -o <file>  -key <public_key_file_1> -key <public_key_file_2> ...,

# Windows OS
virgil encrypt  -i <file> -o <file> -key <public_key_file_1> -key <public_key_file_2> ...,
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
# FreeBSD / Linux / Mac OS
./virgil decrypt  -i <file> -o <file>  -key <private_key_file> -p password,

# Windows OS
virgil decrypt  -i <file> -o <file> -key <private_key_file>  -p password,
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
# FreeBSD / Linux / Mac OS
./virgil sign  -i <file> -o <file>  -key <private_key_file> -p password,

# Windows OS
virgil sign  -i <file> -o <file> -key <private_key_file>  -p password,
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
# FreeBSD / Linux / Mac OS
./virgil verify  -i <file> -s <file>  -key <public_key_file> ,

# Windows OS
virgil verify  -i <file> -s <file> -key <public_key_file> ,
```
```
flags :
-i  - File with data which necessary to verify.
-o  - Digest sign.
-key  - Public key file.  If omitted, stdin is used. 
```


## License
See [LICENSE](https://github.com/VirgilSecurity/virgil-cli/tree/master/LICENSE) for details.

## Support
Our developer support team is here to help you. Find out more information on our [Help Center](https://help.virgilsecurity.com/).

You can find us on [Twitter](https://twitter.com/VirgilSecurity) or send us email support@VirgilSecurity.com.

Also, get extra help from our support team on [Slack](https://virgilsecurity.com/join-community).
