/*
 * Copyright (C) 2015-2018 Virgil Security Inc.
 *
 * Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   (1) Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 *
 *   (2) Redistributions in binary form must reproduce the above copyright
 *   notice, this list of conditions and the following disclaimer in
 *   the documentation and/or other materials provided with the
 *   distribution.
 *
 *   (3) Neither the name of the copyright holder nor the names of its
 *   contributors may be used to endorse or promote products derived
 *   from this software without specific prior written permission.
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
 */

package errors

import "fmt"

// HTTPError stores HTTP Status error.
type HTTPError struct {
	code int
}

// GetCode gets HTTP status code.
func (httpError HTTPError) HTTPErrorCode() int {
	return httpError.code
}

// ServiceError stores Service errors.
type ServiceError struct {
	code int
}

// GetCode gets Service error code.
func (serviceError ServiceError) ServiceErrorCode() int {
	return serviceError.code
}

type SDKError struct {
	HTTPError
	ServiceError
	Message string
}

func (e SDKError) Error() string {
	if e.IsServiceError() {
		return fmt.Sprintf("http status code %d, service code: %d, message: %s", e.HTTPErrorCode(), e.ServiceErrorCode(), e.Message)
	}
	if e.IsHTTPError() {
		return fmt.Sprintf("http error %d", e.HTTPErrorCode())
	}
	return e.Message
}

// IsHTTPError checks if an error is HTTP status code based error.
func (e SDKError) IsHTTPError() bool {
	return e.HTTPError.code != 0
}

// IsServiceError checks if an error is Service error.
func (e SDKError) IsServiceError() bool {
	return e.ServiceError.code != 0
}

// New returns an error that formats as the given text.
func New(message string) error {
	return SDKError{
		Message: message,
	}
}

// NewServiceError returns an Service error.
func NewServiceError(serviceErrorCode int, httpCode int, message string) error {
	return SDKError{
		Message: message,
		ServiceError: ServiceError{
			code: serviceErrorCode,
		},
		HTTPError: HTTPError{
			code: httpCode,
		},
	}
}

// NewHttpError returns an error based on HTTP status code.
func NewHttpError(httpCode int, message string) error {
	return SDKError{
		Message: message,
		HTTPError: HTTPError{
			code: httpCode,
		},
	}
}

func ToSdkError(err error) (SDKError, bool) {
	e, ok := Cause(err).(SDKError)
	return e, ok
}
