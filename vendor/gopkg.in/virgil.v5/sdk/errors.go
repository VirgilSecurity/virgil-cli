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

package sdk

import (
	"errors"

	"gopkg.in/virgil.v5/common"
)

type CardsAPIError common.VirgilAPIError

func (err CardsAPIError) Error() string {
	return common.VirgilAPIError(err).Error()
}

var (
	CSRIdentityEmptyErr        = errors.New("Identity field in CSR is mandatory")
	CSRSignParamIncorrectErr   = errors.New("CSR signature params incorrect")
	CSRPublicKeyEmptyErr       = errors.New("Public key field in CSR is mandatory")
	CSRSelfSignAlreadyExistErr = errors.New("The CSR already has a self signature")
	CSRAppSignAlreadyExistErr  = errors.New("The CSR already has an application signature")

	CardValidationSignerTypeIncorrectErr       = NewCardVerifierError("Card validation: signer type incorrect")
	CardValidationExpectedSignerWasNotFoundErr = NewCardVerifierError("Card validation: expected signer was not found")
	CardValidationSignatureValidationFailedErr = NewCardVerifierError("Card validation: signature validation failed")
)
