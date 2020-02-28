package functional

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/VirgilSecurity/virgil-cli/test/fixtures"
	"github.com/VirgilSecurity/virgil-cli/test/helpers"
	"github.com/VirgilSecurity/virgil-cli/utils"
)

func TestKMSCreate(t *testing.T) {
	ok := helpers.UseApp(UserEmail, UserPassword)
	assert.True(t, ok)

	keyAlias := helpers.GenerateString()[:24]

	cmd := helpers.PrepareCmd("kms", "create", keyAlias)

	cmdOut, _ := cmd.StdoutPipe()
	cmdErr, _ := cmd.StderrPipe()

	if err := cmd.Start(); err != nil {
		fmt.Printf("Cmd failed to start: %+v\n", err)
	}

	scannerOut := bufio.NewScanner(cmdOut)
	scannerErr := bufio.NewScanner(cmdErr)

	scannerOut.Scan()
	kmsKeyInfo := scannerOut.Text()
	if !strings.Contains(kmsKeyInfo, fixtures.KMSKeyInfoPatternShort) {
		fmt.Printf("Unexpected kms key info: %s\n", kmsKeyInfo)
		_ = cmd.Process.Kill()
	}

	scannerOut.Scan()
	kmsKeyCreateOutput := scannerOut.Text()
	assert.Equal(t, utils.KMSKeyCreateSuccess, kmsKeyCreateOutput)

	helpers.CmdKiller(cmd, scannerErr)
	assert.NoError(t, cmd.Wait())
}

func TestKMSClientPrivate(t *testing.T) {
	cmd := helpers.PrepareCmd("kms", "client-private")

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
	assert.NoError(t, err)

	helpers.CmdKiller(cmd, scannerErr)
	assert.NoError(t, cmd.Wait())
}

func TestKMSList(t *testing.T) {
	_, _, ok := helpers.GenerateKMSKey(UserEmail, UserPassword)
	assert.True(t, ok)

	cmd := helpers.PrepareCmd("kms", "list")

	cmdOut, _ := cmd.StdoutPipe()
	cmdErr, _ := cmd.StderrPipe()

	if err := cmd.Start(); err != nil {
		fmt.Printf("Cmd failed to start: %+v\n", err)
	}

	scannerOut := bufio.NewScanner(cmdOut)
	scannerErr := bufio.NewScanner(cmdErr)

	var kmsKeysListOutPut []string
	for scannerOut.Scan() {
		kmsKeysListOutPut = append(kmsKeysListOutPut, scannerOut.Text())
	}
	assert.NotEmpty(t, kmsKeysListOutPut)
	for _, appHeader := range fixtures.KMSKeysListHeaders {
		if len(kmsKeysListOutPut) > 0 {
			assert.True(t, strings.Contains(kmsKeysListOutPut[0], appHeader))
		}
	}
	helpers.CmdKiller(cmd, scannerErr)
	assert.NoError(t, cmd.Wait())
}

func TestKMSGetUpdateToken(t *testing.T) {
	keyAlias, _, ok := helpers.GenerateKMSKey(UserEmail, UserPassword)
	assert.True(t, ok)

	cmd := helpers.PrepareCmd("kms", "get-update-token", keyAlias)

	cmdOut, _ := cmd.StdoutPipe()
	cmdErr, _ := cmd.StderrPipe()

	if err := cmd.Start(); err != nil {
		fmt.Printf("Cmd failed to start: %+v\n", err)
	}

	scannerOut := bufio.NewScanner(cmdOut)
	scannerErr := bufio.NewScanner(cmdErr)

	scannerOut.Scan()
	updateToken := scannerOut.Text()
	_, err := base64.StdEncoding.DecodeString(updateToken)
	assert.NoError(t, err)

	helpers.CmdKiller(cmd, scannerErr)
	assert.NoError(t, cmd.Wait())
}

func TestKMSRotate(t *testing.T) {
	kmsPrivateKey, ok := helpers.GenerateKMSPrivateKey()
	assert.True(t, ok)

	_, kmsPublicKey, updateToken, ok := helpers.GetKMSUpdateToken(UserEmail, UserPassword)
	assert.True(t, ok)

	cmd := helpers.PrepareCmd("kms", "rotate", kmsPrivateKey, kmsPublicKey, updateToken)

	cmdOut, _ := cmd.StdoutPipe()
	cmdErr, _ := cmd.StderrPipe()

	if err := cmd.Start(); err != nil {
		fmt.Printf("Cmd failed to start: %+v\n", err)
	}

	scannerOut := bufio.NewScanner(cmdOut)
	scannerErr := bufio.NewScanner(cmdErr)

	scannerOut.Scan()
	serverPublicKeyOut := scannerOut.Text()
	assert.Equal(t, fixtures.KMSRotateServerPublicKey, serverPublicKeyOut)
	scannerOut.Scan()
	newServerPublicKeyContent := scannerOut.Text()
	assert.NotEmpty(t, newServerPublicKeyContent)
	_, err := base64.StdEncoding.DecodeString(newServerPublicKeyContent)
	assert.NoError(t, err)
	scannerOut.Scan()
	clientPrivateKeyOut := scannerOut.Text()
	assert.Equal(t, fixtures.KMSRotateClientPrivateKey, clientPrivateKeyOut)
	scannerOut.Scan()
	newClientPrivateKeyContent := scannerOut.Text()
	if strings.Contains(newClientPrivateKeyContent, "KS.") {
		newClientPrivateKeyContent = strings.Replace(newClientPrivateKeyContent, "KS.", "", 1)
	}
	assert.NotEmpty(t, newClientPrivateKeyContent)
	_, err = base64.StdEncoding.DecodeString(newClientPrivateKeyContent)
	assert.NoError(t, err)

	helpers.CmdKiller(cmd, scannerErr)
	assert.NoError(t, cmd.Wait())
}

func TestKMSDeleteUpdateToken(t *testing.T) {
	keyAlias, _, _, ok := helpers.GetKMSUpdateToken(UserEmail, UserPassword)
	assert.True(t, ok)

	cmd := helpers.PrepareCmd("kms", "delete-update-token", keyAlias)
	cmdOut, _ := cmd.StdoutPipe()
	cmdErr, _ := cmd.StderrPipe()

	if err := cmd.Start(); err != nil {
		fmt.Printf("Cmd failed to start: %+v\n", err)
	}

	scannerOut := bufio.NewScanner(cmdOut)
	scannerErr := bufio.NewScanner(cmdErr)

	scannerOut.Scan()
	tokenDeleteOutput := scannerOut.Text()
	assert.Equal(t, utils.KMSUpdateTokenDeleteSuccess, tokenDeleteOutput)
	helpers.CmdKiller(cmd, scannerErr)
	assert.NoError(t, cmd.Wait())
}
