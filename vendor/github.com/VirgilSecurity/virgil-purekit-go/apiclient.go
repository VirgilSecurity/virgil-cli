/*
 * Copyright (C) 2015-2018 Virgil Security Inc.
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

package purekit

import (
	"net/http"
	"sync"
)

//APIClient implements API request layer
type APIClient struct {
	AppToken   string
	URL        string
	HTTPClient *VirgilHTTPClient
	once       sync.Once
}

//GetEnrollment receives random enrollment from service
func (c *APIClient) GetEnrollment(req *EnrollmentRequest) (resp *EnrollmentResponse, err error) {
	resp = &EnrollmentResponse{}
	_, err = c.getClient().Send(c.AppToken, http.MethodPost, "/phe/v1/enroll", req, resp)
	return
}

//VerifyPassword does not send password to server, only the part tat server provided in GetEnrollment
func (c *APIClient) VerifyPassword(req *VerifyPasswordRequest) (resp *VerifyPasswordResponse, err error) {
	resp = &VerifyPasswordResponse{}
	_, err = c.getClient().Send(c.AppToken, http.MethodPost, "/phe/v1/verify-password", req, resp)
	return
}

func (c *APIClient) getClient() *VirgilHTTPClient {
	c.once.Do(func() {
		if c.HTTPClient == nil {
			c.HTTPClient = &VirgilHTTPClient{
				Address: c.URL,
			}
		}
	})
	return c.HTTPClient
}
