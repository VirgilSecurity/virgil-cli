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

func TestAppTokenCreate(t *testing.T) {
	appCreateToken(t)
}

func TestAppTokenDelete(t *testing.T) {
	appTokenName := appCreateToken(t)
	cmd := helpers.PrepareCmd("app", "token", "delete", appTokenName)

	cmdOut, _ := cmd.StdoutPipe()
	cmdErr, _ := cmd.StderrPipe()

	if err := cmd.Start(); err != nil {
		fmt.Printf("Cmd failed to start: %+v\n", err)
	}

	scannerOut := bufio.NewScanner(cmdOut)
	scannerErr := bufio.NewScanner(cmdErr)

	scannerOut.Scan()
	tokenDeleteSuccess := scannerOut.Text()

	assert.Equal(t, utils.AppTokenDeleteSuccess, tokenDeleteSuccess)

	helpers.CmdKiller(cmd, scannerErr)
	assert.NoError(t, cmd.Wait())
}

func TestAppTokenList(t *testing.T) {
	appCreateToken(t)

	cmd := helpers.PrepareCmd("app", "token", "list")

	cmdOut, _ := cmd.StdoutPipe()
	cmdErr, _ := cmd.StderrPipe()

	if err := cmd.Start(); err != nil {
		fmt.Printf("Cmd failed to start: %+v\n", err)
	}

	scannerOut := bufio.NewScanner(cmdOut)
	scannerErr := bufio.NewScanner(cmdErr)

	var appTokenListOutPut []string
	for scannerOut.Scan() {
		appTokenListOutPut = append(appTokenListOutPut, scannerOut.Text())
	}
	assert.NotEmpty(t, appTokenListOutPut)
	for _, appTokenHeader := range fixtures.AppTokenListHeaders {
		if len(appTokenListOutPut) > 0 {
			assert.True(t, strings.Contains(appTokenListOutPut[0], appTokenHeader))
		}
	}
	helpers.CmdKiller(cmd, scannerErr)
	assert.NoError(t, cmd.Wait())
}

func appCreateToken(t *testing.T) string {
	helpers.UserLoginByEmail(UserEmail, UserPassword)

	ok := helpers.UseApp(UserEmail, UserPassword)
	assert.True(t, ok)

	appTokenName := helpers.GenerateString()[:24]

	cmd := helpers.PrepareCmd("app", "token", "create", "--name", appTokenName)

	cmdOut, _ := cmd.StdoutPipe()
	cmdErr, _ := cmd.StderrPipe()

	if err := cmd.Start(); err != nil {
		fmt.Printf("Cmd failed to start: %+v\n", err)
	}

	scannerOut := bufio.NewScanner(cmdOut)
	scannerErr := bufio.NewScanner(cmdErr)

	scannerOut.Scan()
	tokenGeneratedSuccess := scannerOut.Text()

	assert.True(t, strings.Contains(tokenGeneratedSuccess, utils.AppTokenCreateSuccess))

	helpers.CmdKiller(cmd, scannerErr)
	assert.NoError(t, cmd.Wait())

	return appTokenName
}
