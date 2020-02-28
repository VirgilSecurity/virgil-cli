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
package functional

import (
	"bufio"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/VirgilSecurity/virgil-cli/test/fixtures"
	"github.com/VirgilSecurity/virgil-cli/test/helpers"
	"github.com/VirgilSecurity/virgil-cli/utils"
)

func TestUsage(t *testing.T) {
	cmd := helpers.PrepareCmd()

	if err := cmd.Start(); err != nil {
		fmt.Printf("Cmd failed to start: %+v\n", err)
	}

	assert.NoError(t, cmd.Wait())
}

func TestVersion(t *testing.T) {
	cmd := helpers.PrepareCmd("-v")
	cmdOutput, err := cmd.Output()
	assert.NoError(t, err)

	assert.Equal(t, fixtures.VersionPattern+utils.Version+"\n", string(cmdOutput))
}

func TestRegister(t *testing.T) {
	cmd := helpers.PrepareCmd("register")

	cmdIn, _ := cmd.StdinPipe()
	cmdOut, _ := cmd.StdoutPipe()
	cmdErr, _ := cmd.StderrPipe()

	if err := cmd.Start(); err != nil {
		fmt.Printf("Cmd failed to start: %+v\n", err)
	}

	testEmail := helpers.GenerateEmail()
	testPassword := helpers.GeneratePassowrd()

	scannerOut := bufio.NewScanner(cmdOut)
	scannerErr := bufio.NewScanner(cmdErr)

	scannerOut.Scan()
	registerPrompt := scannerOut.Text()

	if registerPrompt == utils.EmailPrompt {
		_, _ = cmdIn.Write([]byte(testEmail + "\n"))
	} else {
		fmt.Println("Unexpected register prompt")
		_ = cmd.Process.Kill()
	}

	scannerOut.Scan()
	registerPasswordPrompt := scannerOut.Text()
	if registerPasswordPrompt == utils.PasswordPrompt {
		_, _ = cmdIn.Write([]byte(testPassword + "\n"))
	} else {
		fmt.Println("Unexpected register password prompt")
		_ = cmd.Process.Kill()
	}

	scannerOut.Scan()
	registerAgainPasswordPrompt := scannerOut.Text()
	if registerAgainPasswordPrompt == utils.PasswordConfirmPrompt {
		_, _ = cmdIn.Write([]byte(testPassword + "\n"))
	} else {
		fmt.Println("Unexpected register confirm password prompt")
		_ = cmd.Process.Kill()
	}

	scannerOut.Scan()
	confirmationCodeDescription := scannerOut.Text()
	if confirmationCodeDescription != utils.ConfirmationCodeDescription {
		fmt.Printf("Unexpected confirmation code description: %s\n", confirmationCodeDescription)
		_ = cmd.Process.Kill()
	}

	scannerOut.Scan()
	confirmationCodePrompt := scannerOut.Text()
	if confirmationCodePrompt == utils.ConfirmationCodePrompt {
		time.Sleep(5 * time.Second)
		confirmCode := helpers.GetConfirmCode(testEmail)
		_, _ = cmdIn.Write([]byte(confirmCode + "\n"))
	} else {
		fmt.Printf("Unexpected register confirmation code prompt: %s\n", confirmationCodePrompt)
		_ = cmd.Process.Kill()
	}

	scannerOut.Scan()
	registerOutput := scannerOut.Text()
	assert.Equal(t, utils.AccountSuccessfullyRegistered, registerOutput)

	cmdErrored := helpers.CmdKiller(cmd, scannerErr)

	assert.NoError(t, cmd.Wait())

	if !cmdErrored {
		helpers.UserLoginByEmail(testEmail, testPassword)
	}
}

func TestLogin(t *testing.T) {
	cmd := helpers.PrepareCmd("login")

	cmdIn, _ := cmd.StdinPipe()
	cmdOut, _ := cmd.StdoutPipe()
	cmdErr, _ := cmd.StderrPipe()

	if err := cmd.Start(); err != nil {
		fmt.Printf("Cmd failed to start: %+v\n", err)
	}

	scannerOut := bufio.NewScanner(cmdOut)
	scannerErr := bufio.NewScanner(cmdErr)
	scannerOut.Scan()

	loginPrompt := scannerOut.Text()

	if loginPrompt == utils.EmailPrompt {
		_, _ = cmdIn.Write([]byte(UserEmail + "\n"))
	} else {
		fmt.Println("Unexpected login prompt")
		_ = cmd.Process.Kill()
	}

	scannerOut.Scan()
	passwordPrompt := scannerOut.Text()

	if passwordPrompt == utils.PasswordPrompt {
		_, _ = cmdIn.Write([]byte(UserPassword + "\n"))
	} else {
		fmt.Println("Unexpected password prompt")
		_ = cmd.Process.Kill()
	}

	scannerOut.Scan()
	loginOutput := scannerOut.Text()
	if fmt.Sprintf("%s %s\n", utils.LoginSuccess, UserEmail) != loginOutput {
		_ = cmd.Process.Kill()
	}
	assert.Equal(t, fmt.Sprintf("%s %s", utils.LoginSuccess, UserEmail), loginOutput)

	helpers.CmdKiller(cmd, scannerErr)
	assert.NoError(t, cmd.Wait())
}

func TestLogout(t *testing.T) {
	helpers.UserLoginByEmail(UserEmail, UserPassword)
	cmd := helpers.PrepareCmd("logout")

	cmdOut, _ := cmd.StdoutPipe()
	cmdErr, _ := cmd.StderrPipe()

	if err := cmd.Start(); err != nil {
		fmt.Printf("Cmd failed to start: %+v\n", err)
	}

	scannerOut := bufio.NewScanner(cmdOut)
	scannerErr := bufio.NewScanner(cmdErr)
	scannerOut.Scan()

	logoutOutput := scannerOut.Text()
	assert.Equal(t, utils.LogoutSuccess, logoutOutput)

	helpers.CmdKiller(cmd, scannerErr)

	assert.NoError(t, cmd.Wait())
}

func TestUse(t *testing.T) {
	_, appName, ok := helpers.CreateApp(UserEmail, UserPassword)
	assert.True(t, ok)

	cmd := helpers.PrepareCmd("use", appName)

	cmdOut, _ := cmd.StdoutPipe()
	cmdErr, _ := cmd.StderrPipe()

	if err := cmd.Start(); err != nil {
		fmt.Printf("Cmd failed to start: %+v\n", err)
	}

	scannerOut := bufio.NewScanner(cmdOut)
	scannerErr := bufio.NewScanner(cmdErr)
	scannerOut.Scan()

	appContext := scannerOut.Text()

	if appContext != utils.ApplicationSetContextSuccess {
		_ = cmd.Process.Kill()
	}

	scannerOut.Scan()
	appUseOk := scannerOut.Text()
	assert.Equal(t, utils.UseApplicationWarning, appUseOk)

	helpers.CmdKiller(cmd, scannerErr)
	assert.NoError(t, cmd.Wait())
}

// TODO TestEncrypt

// TODO TestDecrypt

// TODO TestSign

// TODO TestVerify
