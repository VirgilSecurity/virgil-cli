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
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/VirgilSecurity/virgil-cli/test/fixtures"
	"github.com/VirgilSecurity/virgil-cli/test/helpers"
	"github.com/VirgilSecurity/virgil-cli/utils"
)

func TestAppCreate(t *testing.T) {
	helpers.UserLoginByEmail(UserEmail, UserPassword)

	appName := helpers.GenerateString()[:24]

	cmd := helpers.PrepareCmd("app", "create", appName)

	cmdOut, _ := cmd.StdoutPipe()
	cmdErr, _ := cmd.StderrPipe()

	if err := cmd.Start(); err != nil {
		fmt.Printf("Cmd failed to start: %+v\n", err)
	}

	scannerOut := bufio.NewScanner(cmdOut)
	scannerErr := bufio.NewScanner(cmdErr)

	scannerOut.Scan()
	registerdAppIDString := scannerOut.Text()
	assert.True(t, strings.HasPrefix(registerdAppIDString, utils.ApplicationIDOutput))

	scannerOut.Scan()
	appCreateOutput := scannerOut.Text()
	assert.Equal(t, utils.ApplicationCreateSuccess, appCreateOutput)

	helpers.CmdKiller(cmd, scannerErr)
	assert.NoError(t, cmd.Wait())
}

func TestAppList(t *testing.T) {
	helpers.UserLoginByEmail(UserEmail, UserPassword)
	cmd := helpers.PrepareCmd("app", "list")

	cmdOut, _ := cmd.StdoutPipe()
	cmdErr, _ := cmd.StderrPipe()

	if err := cmd.Start(); err != nil {
		fmt.Printf("Cmd failed to start: %+v\n", err)
	}

	scannerOut := bufio.NewScanner(cmdOut)

	scannerErr := bufio.NewScanner(cmdErr)

	var appListOutPut []string
	for scannerOut.Scan() {
		appListOutPut = append(appListOutPut, scannerOut.Text())
	}

	assert.NotEmpty(t, appListOutPut)
	for _, appHeader := range fixtures.AppListHeaders {
		if len(appListOutPut) > 0 {
			assert.True(t, strings.Contains(appListOutPut[0], appHeader))
		}
	}
	helpers.CmdKiller(cmd, scannerErr)
	assert.NoError(t, cmd.Wait())
}

func TestAppDelete(t *testing.T) {
	appID, _, ok := helpers.CreateApp(UserEmail, UserPassword)
	assert.True(t, ok)
	helpers.UserLoginByEmail(UserEmail, UserPassword)

	cmd := helpers.PrepareCmd("app", "delete", appID)

	cmdIn, _ := cmd.StdinPipe()
	cmdOut, _ := cmd.StdoutPipe()
	cmdErr, _ := cmd.StderrPipe()

	if err := cmd.Start(); err != nil {
		fmt.Printf("Cmd failed to start: %+v\n", err)
	}

	scannerOut := bufio.NewScanner(cmdOut)
	scannerErr := bufio.NewScanner(cmdErr)

	scannerOut.Scan()
	appDeletePrompt := scannerOut.Text()
	if strings.Contains(appDeletePrompt, utils.ApplicationDeletePrompt) {
		_, _ = cmdIn.Write([]byte("y" + "\n"))
	} else {
		fmt.Printf("Unexpected app delete prompt: %s\n", appDeletePrompt)
		_ = cmd.Process.Kill()
	}

	scannerOut.Scan()
	appDeletedOutput := scannerOut.Text()
	assert.Equal(t, utils.ApplicationDeleteSuccess, appDeletedOutput)

	helpers.CmdKiller(cmd, scannerErr)
	assert.NoError(t, cmd.Wait())
}
func TestAppUpdate(t *testing.T) {
	appID, _, ok := helpers.CreateApp(UserEmail, UserPassword)
	assert.True(t, ok)
	helpers.UserLoginByEmail(UserEmail, UserPassword)

	cmd := helpers.PrepareCmd("app", "update", appID)

	cmdIn, _ := cmd.StdinPipe()
	cmdOut, _ := cmd.StdoutPipe()
	cmdErr, _ := cmd.StderrPipe()

	if err := cmd.Start(); err != nil {
		fmt.Printf("Cmd failed to start: %+v\n", err)
	}

	scannerOut := bufio.NewScanner(cmdOut)
	scannerErr := bufio.NewScanner(cmdErr)

	scannerOut.Scan()
	appUpdatePrompt := scannerOut.Text()
	if appUpdatePrompt == utils.ApplicationNamePrompt {
		_, _ = cmdIn.Write([]byte("test" + "\n"))
	} else {
		fmt.Printf("Unexpected app update prompt: %s\n", appUpdatePrompt)
		_ = cmd.Process.Kill()
	}

	scannerOut.Scan()
	appUpdatedOutput := scannerOut.Text()
	assert.Equal(t, utils.ApplicationUpdateSuccess, appUpdatedOutput)

	helpers.CmdKiller(cmd, scannerErr)
	assert.NoError(t, cmd.Wait())
}
