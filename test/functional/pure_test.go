package functional

import (
	"bufio"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/VirgilSecurity/virgil-cli/test/helpers"
	"github.com/VirgilSecurity/virgil-cli/utils"
)

func TestPureKeygenSecret(t *testing.T) {
	helpers.UserLoginByEmail(UserEmail, UserPassword)
	cmd := helpers.PrepareCmd("purekit", "keygen", "sk")

	cmdOut, _ := cmd.StdoutPipe()
	cmdErr, _ := cmd.StderrPipe()

	if err := cmd.Start(); err != nil {
		fmt.Printf("Cmd failed to start: %+v\n", err)
	}

	scannerOut := bufio.NewScanner(cmdOut)
	scannerErr := bufio.NewScanner(cmdErr)

	scannerOut.Scan()
	secreteKeyGenerateSuccess := scannerOut.Text()
	assert.Equal(t, utils.PureSecretKeyCreateSuccess, secreteKeyGenerateSuccess)

	helpers.CmdKiller(cmd, scannerErr)
	assert.NoError(t, cmd.Wait())
}

func TestPureKeygenAuth(t *testing.T) {
	helpers.UserLoginByEmail(UserEmail, UserPassword)
	cmd := helpers.PrepareCmd("purekit", "keygen", "ak")

	cmdOut, _ := cmd.StdoutPipe()
	cmdErr, _ := cmd.StderrPipe()

	if err := cmd.Start(); err != nil {
		fmt.Printf("Cmd failed to start: %+v\n", err)
	}

	scannerOut := bufio.NewScanner(cmdOut)
	scannerErr := bufio.NewScanner(cmdErr)

	scannerOut.Scan()
	authKeyGenerateSuccess := scannerOut.Text()
	assert.Equal(t, utils.PureAuthKeyCreateSuccess, authKeyGenerateSuccess)

	helpers.CmdKiller(cmd, scannerErr)
	assert.NoError(t, cmd.Wait())
}

func TestPureKeygenBackup(t *testing.T) {
	helpers.UserLoginByEmail(UserEmail, UserPassword)
	cmd := helpers.PrepareCmd("purekit", "keygen", "bu")

	cmdOut, _ := cmd.StdoutPipe()
	cmdErr, _ := cmd.StderrPipe()

	if err := cmd.Start(); err != nil {
		fmt.Printf("Cmd failed to start: %+v\n", err)
	}

	scannerOut := bufio.NewScanner(cmdOut)
	scannerErr := bufio.NewScanner(cmdErr)

	scannerOut.Scan()
	backupKeyCreateWarning := scannerOut.Text()
	assert.Equal(t, utils.PureBackupKeyCreateWarning, backupKeyCreateWarning)

	scannerOut.Scan()
	backupKeyPublicCreateSuccess := scannerOut.Text()
	assert.True(t, strings.Contains(backupKeyPublicCreateSuccess, utils.PureBackupKeyPublicCreateSuccessTemplate))

	scannerOut.Scan()
	backupKeyPrivateCreateSuccess := scannerOut.Text()
	assert.True(t, strings.Contains(backupKeyPrivateCreateSuccess, utils.PureBackupKeyPrivateCreateSuccessTemplate))

	helpers.CmdKiller(cmd, scannerErr)
	assert.NoError(t, cmd.Wait())
}

// TODO TestPureKeygenHashes

func TestPureKeygenNonRotatableMasterKey(t *testing.T) {
	helpers.UserLoginByEmail(UserEmail, UserPassword)
	cmd := helpers.PrepareCmd("purekit", "keygen", "nm")

	cmdOut, _ := cmd.StdoutPipe()
	cmdErr, _ := cmd.StderrPipe()

	if err := cmd.Start(); err != nil {
		fmt.Printf("Cmd failed to start: %+v\n", err)
	}

	scannerOut := bufio.NewScanner(cmdOut)
	scannerErr := bufio.NewScanner(cmdErr)

	scannerOut.Scan()
	nonRotatableMasterKeySucces := scannerOut.Text()
	assert.True(t, strings.Contains(nonRotatableMasterKeySucces, utils.PureNMSKeyCreateSuccessTemplate))

	helpers.CmdKiller(cmd, scannerErr)
	assert.NoError(t, cmd.Wait())
}

func TestPureKeygenSigning(t *testing.T) {
	helpers.UserLoginByEmail(UserEmail, UserPassword)
	cmd := helpers.PrepareCmd("purekit", "keygen", "signing")

	cmdOut, _ := cmd.StdoutPipe()
	cmdErr, _ := cmd.StderrPipe()

	if err := cmd.Start(); err != nil {
		fmt.Printf("Cmd failed to start: %+v\n", err)
	}

	scannerOut := bufio.NewScanner(cmdOut)
	scannerErr := bufio.NewScanner(cmdErr)

	scannerOut.Scan()
	storageSigningKeyPair := scannerOut.Text()
	assert.True(t, strings.Contains(storageSigningKeyPair, utils.PureStorageKeyPairCreateSuccessTemplate))

	helpers.CmdKiller(cmd, scannerErr)
	assert.NoError(t, cmd.Wait())
}

func TestPureKeygenOwn(t *testing.T) {
	helpers.UserLoginByEmail(UserEmail, UserPassword)
	cmd := helpers.PrepareCmd("purekit", "keygen", "own")

	cmdOut, _ := cmd.StdoutPipe()
	cmdErr, _ := cmd.StderrPipe()

	if err := cmd.Start(); err != nil {
		fmt.Printf("Cmd failed to start: %+v\n", err)
	}

	scannerOut := bufio.NewScanner(cmdOut)
	scannerErr := bufio.NewScanner(cmdErr)

	scannerOut.Scan()
	ownSigningKeyPair := scannerOut.Text()
	assert.True(t, strings.Contains(ownSigningKeyPair, utils.PureOwnSigningKeyCreateSuccessTemplate))

	helpers.CmdKiller(cmd, scannerErr)
	assert.NoError(t, cmd.Wait())
}

func TestPureKeygenAll(t *testing.T) {
	helpers.UserLoginByEmail(UserEmail, UserPassword)
	cmd := helpers.PrepareCmd("purekit", "keygen", "all")

	cmdOut, _ := cmd.StdoutPipe()
	cmdErr, _ := cmd.StderrPipe()

	if err := cmd.Start(); err != nil {
		fmt.Printf("Cmd failed to start: %+v\n", err)
	}

	scannerOut := bufio.NewScanner(cmdOut)
	scannerErr := bufio.NewScanner(cmdErr)

	scannerOut.Scan()
	_ = scannerOut.Text()

	scannerOut.Scan()
	backupKeyCreateWarning := scannerOut.Text()
	assert.Equal(t, utils.PureBackupKeyCreateWarning, backupKeyCreateWarning)

	scannerOut.Scan()
	backupKeyPublicCreateSuccess := scannerOut.Text()
	assert.True(t, strings.Contains(backupKeyPublicCreateSuccess, utils.PureBackupKeyPublicCreateSuccessTemplate))

	scannerOut.Scan()
	backupKeyPrivateCreateSuccess := scannerOut.Text()
	assert.True(t, strings.Contains(backupKeyPrivateCreateSuccess, utils.PureBackupKeyPrivateCreateSuccessTemplate))

	for i := 0; i < 4; i++ {
		scannerOut.Scan()
		_ = scannerOut.Text()
	}

	scannerOut.Scan()
	secreteKeyGenerateSuccess := scannerOut.Text()
	assert.Equal(t, utils.PureSecretKeyCreateSuccess, secreteKeyGenerateSuccess)

	helpers.CmdKiller(cmd, scannerErr)
	assert.NoError(t, cmd.Wait())
}

// TODO TestPureRotate
