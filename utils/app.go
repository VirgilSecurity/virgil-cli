/*
 * Copyright (C) 2015-2019 Virgil Security Inc.
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

package utils

import (
	"encoding/json"
	"fmt"
	"github.com/VirgilSecurity/virgil-cli/client"
	"github.com/VirgilSecurity/virgil-cli/models"
	"github.com/google/uuid"
	"github.com/pkg/errors"
	"io/ioutil"
	"net/http"
	"os"
	"os/user"
	"path/filepath"
)

/*
 * Copyright (C) 2015-2019 Virgil Security Inc.
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

func SaveDefaultApp(vcli *client.VirgilHttpClient, app *models.Application) error {

	u, err := user.Current()
	if err != nil {
		return err
	}

	appIDPath := filepath.Join(u.HomeDir, ".virgil_app")

	if _, err := os.Stat(appIDPath); os.IsNotExist(err) {
		if err = os.Mkdir(appIDPath, 0700); err != nil {
			return err
		}
	}

	var apps []*models.StoredApplication

	appIDPath = filepath.Join(appIDPath, "virgil_app")
	appAlreadyInList := false
	jsonBody, err := ioutil.ReadFile(appIDPath)
	if err == nil {
		if err = json.Unmarshal(jsonBody, &apps); err == nil {
			for _, a := range apps {
				if a.Name == app.Name {
					a.IsDefault = true
					appAlreadyInList = true
				} else {
					a.IsDefault = false
				}
			}
		}
	}

	if !appAlreadyInList {
		a := &models.StoredApplication{
			ID:        app.ID,
			Name:      app.Name,
			CreatedAt: app.CreatedAt,
		}
		a.Token, err = createFunc(app.ID, "CLI_"+uuid.New().String(), vcli)
		if err != nil {
			return err
		}
		a.IsDefault = true
		apps = append(apps, a)
	}

	jsonBody, err = json.Marshal(apps)
	if err != nil {
		return err
	}
	if err = ioutil.WriteFile(appIDPath, jsonBody, 0600); err != nil {
		return err
	}
	return nil
}

func LoadDefaultApp() (app *models.StoredApplication, err error) {
	u, err := user.Current()
	if err != nil {
		return nil, err
	}

	tokenPath := filepath.Join(u.HomeDir, ".virgil_app")

	if _, err := os.Stat(tokenPath); os.IsNotExist(err) {
		return nil, errors.New("virgil_app folder does not exist")
	}

	tokenPath = filepath.Join(tokenPath, "virgil_app")

	if jsonBody, err := ioutil.ReadFile(tokenPath); err != nil {
		return nil, err
	} else {
		apps := make([]*models.StoredApplication, 0)
		if err = json.Unmarshal(jsonBody, &apps); err != nil {
			fmt.Println(err)
			return nil, err
		}
		for _, a := range apps {
			if a.IsDefault {
				return a, nil
			}
		}
		return nil, errors.New("there is no default application")
	}
}

func DeleteAppFile() error {
	u, err := user.Current()
	if err != nil {
		return err
	}

	appIDPath := filepath.Join(u.HomeDir, ".virgil_app")

	if _, err := os.Stat(appIDPath); os.IsNotExist(err) {
		return errors.New(".virgil_app directory does not exist")
	}

	appIDPath = filepath.Join(appIDPath, "virgil_app")

	return os.Remove(appIDPath)
}

func DeleteDefaultApp() error {
	u, err := user.Current()
	if err != nil {
		return err
	}

	appIDPath := filepath.Join(u.HomeDir, ".virgil_app")

	if _, err := os.Stat(appIDPath); os.IsNotExist(err) {
		return errors.New(".virgil_app directory does not exist")
	}

	appIDPath = filepath.Join(appIDPath, "virgil_app")

	var apps []*models.StoredApplication

	jsonBody, err := ioutil.ReadFile(appIDPath)
	if err == nil {
		if err = json.Unmarshal(jsonBody, &apps); err != nil {
			return err
		}
		for _, a := range apps {
			a.IsDefault = false
		}
	} else {
		return nil
	}

	jsonBody, err = json.Marshal(apps)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(appIDPath, jsonBody, 0600);
}

func createFunc(appID, name string, vcli *client.VirgilHttpClient) (token string, err error) {

	req := &models.CreateAppTokenRequest{Name: name, ApplicationID: appID}
	resp := &models.ApplicationToken{}

	_, _, err = SendWithCheckRetry(vcli, http.MethodPost, "/application/"+appID+"/tokens", req, resp)

	fmt.Println("here")
	if err != nil {
		return "", err
	}
	if resp != nil {
		return resp.Token, nil
	}

	return "", errors.New("empty response")
}
