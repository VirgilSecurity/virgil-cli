# Virgil PureKit Go SDK

[![Build Status](https://travis-ci.com/VirgilSecurity/virgil-purekit-go.png?branch=master)](https://travis-ci.com/VirgilSecurity/virgil-purekit-go)
[![GitHub license](https://img.shields.io/badge/license-BSD%203--Clause-blue.svg)](https://github.com/VirgilSecurity/virgil/blob/master/LICENSE)


[Introduction](#introduction) | [Features](#features) | [Register Your Account](#register-your-account) | [Install and configure SDK](#install-and-configure-sdk) | [Prepare Your Database](#prepare-your-database) | [Usage Examples](#usage-examples) | [Docs](#docs) | [Support](#support)

## Introduction
<a href="https://purekit.io/"><img width="260px" src="https://cdn.virgilsecurity.com/assets/images/github/logos/pure_grey_logo.png" align="left" hspace="0" vspace="0"></a>[Virgil Security](https://virgilsecurity.com) introduces an implementation of the [Password-Hardened Encryption (PHE) protocol](https://virgilsecurity.com/wp-content/uploads/2018/11/PHE-Whitepaper-2018.pdf) – a new mechanism that secures users' sensitive data and lessens the security risks associated with weak passwords.

Virgil PureKit allows developers to protect user passwords and sensitive data from offline/online attacks and makes stolen passwords useless if your database has been compromised. Neither Virgil nor attackers know anything about users' passwords.

**Authors of the PHE protocol**: Russell W. F. Lai, Christoph Egger, Manuel Reinert, Sherman S. M. Chow, Matteo Maffei and Dominique Schroder.

## Features
- Zero knowledge of user password
- Protection from online attacks
- Protection from offline attacks
- Instant invalidation of stolen database
- User data encryption with a personal key

## Register Your Account
Before starting practicing with the SDK and usage examples make sure that:
- you have a registered Virgil Account at [Virgil Dashboard](https://dashboard.virgilsecurity.com/)
- you created PURE Application
- and you got your PURE Application's credentials, such as: `App Secret Key`, `Service Public Key`, `App Token`


## Install and Configure SDK
The PureKit Go SDK is provided as a package named `purekit`. The package is distributed via GitHub. The package is available for Go 1.10 or newer.


### Install SDK Package
Install PureKit SDK library with the following code:
```bash
go get -u github.com/VirgilSecurity/virgil-purekit-go
```
PureKit uses Dep to do manage its dependencies:
Please install [dep](https://golang.github.io/dep/docs/installation.html) and run the following commands:
```bash
cd $(go env GOPATH)/src/github.com/VirgilSecurity/virgil-purekit-go
dep ensure
```


### Configure SDK
Here is an example of how to specify your credentials SDK class instance:
```go
// here set your purekit credentials
import (
    "github.com/VirgilSecurity/virgil-purekit-go"
)

func InitPureKit() (*purekit.Protocol, error){
    appToken := "AT.OSoPhirdopvijQlFPKdlSydN9BUrn5oEuDwf3Hqps"
    appSecretKey := "SK.1.xacDjofLr2JOu2Vf1+MbEzpdtEP1kUefA0PUJw2UyI0="
    servicePublicKey := "PK.1.BEn/hnuyKV0inZL+kaRUZNvwQ/jkhDQdALrw6VdfvhZhPQQHWyYO+fRlJYZweUz1FGH3WxcZBjA0tL4wn7kE0ls="

    context, err := purekit.CreateContext(appToken, servicePublicKey, appSecretKey, "")
    if err != nil{
        return nil, err
    }

    return purekit.NewProtocol(context)
}
```



## Prepare Your Database
PureKit SDK allows you to easily perform all the necessary operations to create, verify and rotate user's `record`.

**PureKit record** - a user's password that is protected with our PureKit technology. PureKit `record` contains a version, client & server random salts and two values obtained during execution of the PHE protocol.

In order to create and work with user's `record` you have to set up your database with an additional column.

The column must have the following parameters:
<table class="params">
<thead>
		<tr>
			<th>Parameters</th>
			<th>Type</th>
			<th>Size (bytes)</th>
			<th>Description</th>
		</tr>
</thead>

<tbody>
<tr>
	<td>purekit_record</td>
	<td>bytearray</td>
	<td>210</td>
	<td> A unique record, namely a user's protected purekit.</td>
</tr>

</tbody>
</table>


## Usage Examples

### Enroll User Record

Use this flow to create a new PureKit `record` in your DB for a user.

> Remember, if you already have a database with user passwords, you don't have to wait until a user logs in into your system to implement PureKit technology. You can go through your database and enroll (create) a user's `record` at any time.

So, in order to create a `record` for a new database or available one, go through the following operations:
- Take a user's **password** (or its hash or whatever you use) and pass it into the `EnrollAccount` function of SDK on your Server side.
- PureKit SDK will send a request to PHE Service to get enrollment.
- Then, PureKit SDK will create a user's `record`. You need to store this unique user's `record` in your database in associated column.

```go
package main

import (
    "encoding/base64"
    "fmt"
    "github.com/VirgilSecurity/virgil-purekit-go"
    "github.com/VirgilSecurity/virgil-phe-go"
)

// create a new encrypted password record using user password or its hash
func EnrollAccount(password string, prot *purekit.Protocol) error{
    
    record, key, err := prot.EnrollAccount(password)
    if err != nil {
        return err
    }

    //save record to database
    fmt.Printf("Database record:\n%s\n", base64.StdEncoding.EncodeToString(record))
    //use encryptionKey for protecting user data
    encrypted, err := phe.Encrypt(data, key)
    ...

}
```

When you've created a PureKit `record` for all users in your DB, you can delete the unnecessary column where user passwords were previously stored.


### Verify User Record

Use this flow when a user already has his or her own PureKit `record` in your database. This function allows you to verify user's password with the `record` from your DB every time when the user signs in. You have to pass his or her `record` from your DB into the `VerifyPassword` function:

```go
package main

import (
    "fmt"
    "github.com/VirgilSecurity/virgil-purekit-go"
    "github.com/VirgilSecurity/virgil-phe-go"
)


func VerifyPassword(password string, record []byte, prot *purekit.Protocol) error{
    key, err := prot.VerifyPassword(password, record)
    if err != nil {

        if err == purekit.ErrInvalidPassword{
            //invalid password
        }
        return err //some other error
    }

    //use encryptionKey for decrypting user data
    decrypted, err := phe.Decrypt(encrypted, key)
    ...

}
```

## Encrypt user data in your database

Not only user's password is a sensitive data. In this flow we will help you to protect any Personally identifiable information (PII) in your database.

PII is a data that could potentially identify a specific individual, and PII can be sensitive.
Sensitive PII is information which, when disclosed, could result in harm to the individual whose privacy has been breached. Sensitive PII should therefore be encrypted in transit and when data is at rest. Such information includes biometric information, medical information, personally identifiable financial information (PIFI) and unique identifiers such as passport or Social Security numbers.

PureKit service allows you to protect user's PII (personal data) with a user's `encryptionKey` that is obtained from `EnrollAccount` or `VerifyPassword` functions. The `encryptionKey` will be the same for both functions.

In addition, this key is unique to a particular user and won't be changed even after rotating (updating) the user's `record`. The `encryptionKey` will be updated after user changes own password.

Here is an example of data encryption/decryption with an `encryptionKey`:

```go
package main

import (
    "fmt"
    "github.com/VirgilSecurity/virgil-phe-go"
)

func main() {

    //key is obtained from proto.EnrollAccount() or proto.VerifyPassword() calls

    data := []byte("Personal data")

    ciphertext, err := phe.Encrypt(data, encryptionKey)
    if err != nil {
        panic(err)
    }
    decrypted, err := phe.Decrypt(ciphertext, encryptionKey)
    if err != nil {
        panic(err)
    }

    //use decrypted data
}
```
Encryption is performed using AES256-GCM with key & nonce derived from the user's encryptionKey using HKDF and random 256-bit salt.

Virgil Security has Zero knowledge about a user's `encryptionKey`, because the key is calculated every time when you execute `EnrollAccount` or `VerifyPassword` functions at your server side.


## Rotate app keys and user record
There can never be enough security, so you should rotate your sensitive data regularly (about once a week). Use this flow to get an `UPDATE_TOKEN` for updating user's PureKit `RECORD` in your database and to get a new `APP_SECRET_KEY` and `SERVICE_PUBLIC_KEY` of a specific application.

Also, use this flow in case your database has been COMPROMISED!

> This action doesn't require to create an additional table or to do any modification with available one. When a user needs to change his or her own password, use the EnrollAccount function to replace user's oldRecord value in your DB with a newRecord.

There is how it works:

**Step 1.** Get your `UPDATE_TOKEN` using [PureKit CLI](https://github.com/VirgilSecurity/virgil-cli/releases)

Move to your Application panel and press “Show update token” button to get the `update_token`.

./purekit login my@email.com
purekit login my@email.com
./purekit application rotate <app_token>
purekit application rotate <app_token>
**Step 2.** Initialize PureKit SDK with the `UPDATE_TOKEN`.
Move to PureKit SDK configuration file and specify your `UPDATE_TOKEN`:

```go
// here set your purekit credentials
import (
    "github.com/VirgilSecurity/virgil-purekit-go"
)

func InitPassw0rd() (*purekit.Protocol, error){
    appToken := "AT.0000000irdopvijQlFPKdlSydN9BUrn5oEuDwf3Hqps"
    appSecretKey := "SK.1.000jofLr2JOu2Vf1+MbEzpdtEP1kUefA0PUJw2UyI0="
    servicePublicKey := "PK.1.BEn/hnuyKV0inZL+kaRUZNvwQ/jkhDQdALrw6Vdf00000QQHWyYO+fRlJYZweUz1FGH3WxcZBjA0tL4wn7kE0ls="
    updateToken := "UT.2.00000000+0000000000000000000008UfxXDUU2FGkMvKhIgqjxA+hsAtf17K5j11Cnf07jB6uVEvxMJT0lMGv00000="

    context, err := purekit.CreateContext(appToken, servicePublicKey, appSecretKey, updateToken)
    if err != nil{
        return nil, err
    }

    return purekit.NewProtocol(context)
}
```

**Step 3.** Start migration. Use the `NewRecordUpdater("UPDATE_TOKEN")` SDK function to create an instance of class that will update your old records to new ones (you don't need to ask your users to create a new password). The `UpdateRecord()` function requires user's `oldRecord` from your DB:

```go
package main

import (
    "crypto/subtle"
    "github.com/VirgilSecurity/virgil-purekit-go"
)

func main(){
	
	updater, err := purekit.NewRecordUpdater("UPDATE_TOKEN")
	if err != nil{
            //something went wrong
    }
	
    //for each record
    //get old record from the database
    oldRecord := ...

    //update old record
    newRecord, err := updater.UpdateRecord(oldRecord)
    if err != nil{
        //something went wrong
    }

    // newRecord is nil ONLY if oldRecord is already the latest version
    if newRecord != nil{
        //save new record to the database
        saveNewRecord(newRecord)
    }

}
```

So, run the `UpdateRecord()` function and save user's `newRecord` into your database.

Since the SDK is able to work simultaneously with two versions of user's records (`newRecord` and `oldRecord`), this will not affect the backend or users. This means, if a user logs into your system when you do the migration, the PureKit SDK will verify his password without any problems because PHE Service can work with both user's records (`newRecord` and `oldRecord`).

**Step 4.** Get a new `APP_SECRET_KEY` and `SERVICE_PUBLIC_KEY` of a specific application

Use Virgil CLI `update-keys` command and your `UPDATE_TOKEN` to update the `APP_SECRET_KEY` and `SERVICE_PUBLIC_KEY`:

```bash
// FreeBSD / Linux / Mac OS
./purekit application update-keys <service_public_key> <app_secret_key> <update_token>

// Windows OS
purekit application update-keys <service_public_key> <app_secret_key> <update_token>
```

**Step 5.** Move to PureKit SDK configuration and replace your previous `APP_SECRET_KEY`,  `SERVICE_PUBLIC_KEY` with a new one (`APP_TOKEN` will be the same). Delete previous `APP_SECRET_KEY`, `SERVICE_PUBLIC_KEY` and `UPDATE_TOKEN`.

```go
// here set your purekit credentials
import (
    "github.com/VirgilSecurity/virgil-purekit-go"
)

func InitPassw0rd() (*purekit.Protocol, error){
    appToken := "APP_TOKEN_HERE"
    appSecretKey := "NEW_APP_SECRET_KEY_HERE"
    servicePublicKey := "NEW_SERVICE_PUBLIC_KEY_HERE"


    context, err := purekit.CreateContext(appToken, servicePublicKey, appSecretKey, "")
    if err != nil{
        return nil, err
    }

    return purekit.NewProtocol(context)
}
```



## Docs
* [Passw0rd community][_passw0rd] home page
* [The PHE WhitePaper](https://virgilsecurity.com/wp-content/uploads/2018/11/PHE-Whitepaper-2018.pdf) - foundation principles of the protocol

## License

This library is released under the [3-clause BSD License](LICENSE.md).

## Support
Our developer support team is here to help you. Find out more information on our [Help Center](https://help.virgilsecurity.com/).

You can find us on [Twitter](https://twitter.com/VirgilSecurity) or send us email support@VirgilSecurity.com.

Also, get extra help from our support team on [Slack](https://virgilsecurity.com/join-community).
