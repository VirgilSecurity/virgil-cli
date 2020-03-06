/*
 * Copyright (C) 2015-2020 Virgil Security Inc.
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 *     (1) Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *
 *     (2) Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *
 *     (3) Neither the name of the copyright holder nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ''AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
 */
package helpers

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/VirgilSecurity/virgil-cli/test/fixtures"
	"github.com/VirgilSecurity/virgil-cli/utils"
)

func UserLoginByEmail(email, password string) (ok bool) {
	cmd := PrepareCmd("login")

	cmdIn, _ := cmd.StdinPipe()
	cmdOut, _ := cmd.StdoutPipe()

	_ = cmd.Start()

	scannerOut := bufio.NewScanner(cmdOut)
	scannerOut.Scan()

	loginPrompt := scannerOut.Text()

	if loginPrompt == utils.EmailPrompt {
		_, _ = cmdIn.Write([]byte(email + "\n"))
	} else {
		_ = cmd.Process.Kill()
	}

	scannerOut.Scan()
	passwordPrompt := scannerOut.Text()

	if passwordPrompt == utils.PasswordPrompt {
		_, _ = cmdIn.Write([]byte(password + "\n"))
	} else {
		_ = cmd.Process.Kill()
	}

	scannerOut.Scan()
	loginOutput := scannerOut.Text()
	if loginOutput != fmt.Sprintf("%s %s\n", utils.LoginSuccess, email) {
		return false
	}
	_ = cmd.Wait()
	return true
}

func RegisterUser(email, password string) (ok bool) {
	cmd := PrepareCmd("register")

	cmdIn, _ := cmd.StdinPipe()
	cmdOut, _ := cmd.StdoutPipe()
	cmdErr, _ := cmd.StderrPipe()

	_ = cmd.Start()

	scannerOut := bufio.NewScanner(cmdOut)
	scannerErr := bufio.NewScanner(cmdErr)

	scannerOut.Scan()
	registerPrompt := scannerOut.Text()

	if registerPrompt == utils.EmailPrompt {
		_, _ = cmdIn.Write([]byte(email + "\n"))
	} else {
		_ = cmd.Process.Kill()
	}

	scannerOut.Scan()
	registerPasswordPrompt := scannerOut.Text()
	if registerPasswordPrompt == utils.PasswordPrompt {
		_, _ = cmdIn.Write([]byte(password + "\n"))
	} else {
		_ = cmd.Process.Kill()
	}

	scannerOut.Scan()
	registerAgainPasswordPrompt := scannerOut.Text()
	if registerAgainPasswordPrompt == utils.PasswordConfirmPrompt {
		_, _ = cmdIn.Write([]byte(password + "\n"))
	} else {
		_ = cmd.Process.Kill()
	}

	scannerOut.Scan()
	confirmationCodeDescription := scannerOut.Text()
	if confirmationCodeDescription != utils.ConfirmationCodeDescription {
		_ = cmd.Process.Kill()
	}

	scannerOut.Scan()
	confirmationCodePrompt := scannerOut.Text()
	if confirmationCodePrompt == utils.ConfirmationCodePrompt {
		time.Sleep(5 * time.Second)
		confirmCode := GetConfirmCode(email)
		_, _ = cmdIn.Write([]byte(confirmCode + "\n"))
	} else {
		_ = cmd.Process.Kill()
	}

	scannerOut.Scan()
	registerOutput := scannerOut.Text()
	if utils.AccountSuccessfullyRegistered != registerOutput {
		return false
	}

	cmdErrored := CmdKiller(cmd, scannerErr)

	_ = cmd.Wait()

	if !cmdErrored {
		UserLoginByEmail(email, password)
	}
	return true
}

func CreateApp(email, password string) (appID, appName string, ok bool) {
	UserLoginByEmail(email, password)

	appName = GenerateString()[:24]

	cmd := PrepareCmd("app", "create", appName)

	cmdOut, _ := cmd.StdoutPipe()
	cmdErr, _ := cmd.StderrPipe()

	if err := cmd.Start(); err != nil {
		fmt.Printf("Cmd failed to start: %+v\n", err)
	}

	scannerOut := bufio.NewScanner(cmdOut)
	scannerErr := bufio.NewScanner(cmdErr)

	scannerOut.Scan()
	registerdAppIDString := scannerOut.Text()
	if !strings.HasPrefix(registerdAppIDString, utils.ApplicationIDOutput) {
		return appID, appName, false
	}
	appID = strings.TrimPrefix(registerdAppIDString, utils.ApplicationIDOutput+" ")

	scannerOut.Scan()
	appCreateOutput := scannerOut.Text()
	if utils.ApplicationCreateSuccess != appCreateOutput {
		return appID, appName, false
	}

	CmdKiller(cmd, scannerErr)
	err := cmd.Wait()
	if err != nil {
		return appID, appName, false
	}
	return appID, appName, true
}

func UseApp(email, password string) (ok bool) {
	_, appName, _ := CreateApp(email, password)

	cmd := PrepareCmd("use", appName)

	cmdOut, _ := cmd.StdoutPipe()
	cmdErr, _ := cmd.StderrPipe()

	_ = cmd.Start()

	scannerOut := bufio.NewScanner(cmdOut)
	scannerErr := bufio.NewScanner(cmdErr)
	scannerOut.Scan()

	appContext := scannerOut.Text()

	if appContext != utils.ApplicationSetContextSuccess {
		_ = cmd.Process.Kill()
	}

	scannerOut.Scan()
	appUseOk := scannerOut.Text()
	if utils.UseApplicationWarning != appUseOk {
		return false
	}

	CmdKiller(cmd, scannerErr)
	_ = cmd.Wait()
	return true
}

func GenerateKMSKey(email, password string) (keyAlias, keyContent string, ok bool) {
	ok = UseApp(email, password)
	if !ok {
		return keyAlias, keyContent, ok
	}

	keyAlias = GenerateString()[:24]

	cmd := PrepareCmd("kms", "create", keyAlias)

	cmdOut, _ := cmd.StdoutPipe()
	cmdErr, _ := cmd.StderrPipe()

	_ = cmd.Start()

	scannerOut := bufio.NewScanner(cmdOut)
	scannerErr := bufio.NewScanner(cmdErr)

	scannerOut.Scan()
	kmsKeyInfo := scannerOut.Text()
	if !strings.Contains(kmsKeyInfo, fixtures.KMSKeyInfoPatternShort) {
		_ = cmd.Process.Kill()
	}

	keyContent = strings.Replace(
		kmsKeyInfo,
		fmt.Sprintf(fixtures.KMSKeyInfoPattern, strings.ToUpper(keyAlias)), "",
		1,
	)

	scannerOut.Scan()
	kmsKeyCreateOutput := scannerOut.Text()
	if utils.KMSKeyCreateSuccess != kmsKeyCreateOutput {
		return keyAlias, keyContent, false
	}

	CmdKiller(cmd, scannerErr)
	_ = cmd.Wait()
	return keyAlias, keyContent, true
}

func GenerateKMSPrivateKey() (keyContent string, ok bool) {
	cmd := PrepareCmd("kms", "client-private")

	cmdOut, _ := cmd.StdoutPipe()
	cmdErr, _ := cmd.StderrPipe()

	if err := cmd.Start(); err != nil {
		fmt.Printf("Cmd failed to start: %+v\n", err)
	}

	scannerOut := bufio.NewScanner(cmdOut)
	scannerErr := bufio.NewScanner(cmdErr)

	scannerOut.Scan()
	clientPrivateKey := scannerOut.Text()
	_, err := base64.StdEncoding.DecodeString(clientPrivateKey)
	if err != nil {
		return keyContent, false
	}

	CmdKiller(cmd, scannerErr)
	return clientPrivateKey, true
}

func GetKMSUpdateToken(email, password string) (keyAlias, publicKey, updateToken string, ok bool) {
	keyAlias, publicKey, ok = GenerateKMSKey(email, password)
	if !ok {
		return keyAlias, publicKey, updateToken, ok
	}

	cmd := PrepareCmd("kms", "get-update-token", keyAlias)

	cmdOut, _ := cmd.StdoutPipe()
	cmdErr, _ := cmd.StderrPipe()

	if err := cmd.Start(); err != nil {
		fmt.Printf("Cmd failed to start: %+v\n", err)
	}

	scannerOut := bufio.NewScanner(cmdOut)
	scannerErr := bufio.NewScanner(cmdErr)

	scannerOut.Scan()
	updateToken = scannerOut.Text()
	if updateToken == "" {
		return keyAlias, publicKey, updateToken, ok
	}
	_, err := base64.StdEncoding.DecodeString(updateToken)
	if err != nil {
		return keyAlias, publicKey, updateToken, ok
	}

	CmdKiller(cmd, scannerErr)
	_ = cmd.Wait()
	return keyAlias, publicKey, updateToken, true
}
