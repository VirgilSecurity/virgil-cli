/**
 * Copyright (C) 2016 Virgil Security Inc.
 *
 * Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
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
 */

namespace cli {

enum class ExitCode {
    /* successful termination */
    EXIT_OK = 0,

    /* command line usage error */
    EXIT_USAGE = 64,

    /* data format error */
    EXIT_DATAERR = 65,

    /* cannot open input */
    EXIT_NOINPUT = 66,

    /* addressee unknown */
    EXIT_NOUSER = 67,

    /* host name unknown */
    EXIT_NOHOST = 68,

    /* service unavailable */
    EXIT_UNAVAILABLE = 69,

    /* internal software error */
    EXIT_SOFTWARE = 70,

    /* system error (e.g., can't fork) */
    EXIT_OSERR = 71,

    /* critical OS file missing */
    EXIT_OSFILE = 72,

    /* can't create (user) output file */
    EXIT_CANTCREAT = 73,

    /* input/output error */
    EXIT_IOERR = 74,

    /* temp failure; user is invited to retry */
    EXIT_TEMPFAIL = 75,

    /* remote error in protocol */
    EXIT_PROTOCOL = 76,

    /* permission denied */
    EXIT_NOPERM = 77,

    /* configuration error */
    EXIT_CONFIG = 78
};
}
