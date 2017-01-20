/**
 * Copyright (C) 2015-2016 Virgil Security Inc.
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

#ifndef VIRGIL_CLI_LOGGER_H
#define VIRGIL_CLI_LOGGER_H

#include <tinyformat/tinyformat.h>
#include <easylogging/easylogging++.h>

namespace cli { namespace io {

class UserLogDispatchCallback : public el::LogDispatchCallback {
protected:
    virtual void handle(const el::LogDispatchData* dispatchData) override;
};

}}

// Logger id
static constexpr const char kLoggerId_User[] = "user";
static constexpr const char kLoggerCallbackId_User[] = "user_log_callback";

#define ELPP_WRITE_ULOG(writer, level, dispatchAction, vlevel, ...) \
writer(level, __FILE__, __LINE__, ELPP_FUNC, dispatchAction, vlevel).construct(el_getVALength(__VA_ARGS__), __VA_ARGS__)

// Normal logs
#if ELPP_INFO_LOG
#   define UCINFO(writer, dispatchAction, vlevel, ...) ELPP_WRITE_ULOG(writer, el::Level::Info, dispatchAction, vlevel, __VA_ARGS__)
#else
#   define UCINFO(writer, dispatchAction, vlevel, ...) el::base::NullWriter()
#endif  // ELPP_INFO_LOG
#if ELPP_WARNING_LOG
#   define UCWARNING(writer, dispatchAction, vlevel, ...) ELPP_WRITE_ULOG(writer, el::Level::Warning, dispatchAction, vlevel, __VA_ARGS__)
#else
#   define UCWARNING(writer, dispatchAction, vlevel, ...) el::base::NullWriter()
#endif  // ELPP_WARNING_LOG
#if ELPP_DEBUG_LOG
#   define UCDEBUG(writer, dispatchAction, vlevel, ...) ELPP_WRITE_ULOG(writer, el::Level::Debug, dispatchAction, vlevel, __VA_ARGS__)
#else
#   define UCDEBUG(writer, dispatchAction, vlevel, ...) el::base::NullWriter()
#endif  // ELPP_DEBUG_LOG
#if ELPP_ERROR_LOG
#   define UCERROR(writer, dispatchAction, vlevel, ...) ELPP_WRITE_ULOG(writer, el::Level::Error, dispatchAction, vlevel, __VA_ARGS__)
#else
#   define UCERROR(writer, dispatchAction, vlevel, ...) el::base::NullWriter()
#endif  // ELPP_ERROR_LOG
#if ELPP_FATAL_LOG
#   define UCFATAL(writer, dispatchAction, vlevel, ...) ELPP_WRITE_ULOG(writer, el::Level::Fatal, dispatchAction, vlevel, __VA_ARGS__)
#else
#   define UCFATAL(writer, dispatchAction, vlevel, ...) el::base::NullWriter()
#endif  // ELPP_FATAL_LOG
#if ELPP_TRACE_LOG
#   define UCTRACE(writer, dispatchAction, vlevel, ...) ELPP_CURR_FILE_LOGGER_ID, kLoggerId_User(writer, el::Level::Info, dispatchAction, vlevel, __VA_ARGS__)
#else
#   define UCTRACE(writer, dispatchAction, vlevel, ...) el::base::NullWriter()
#endif  // ELPP_TRACE_LOG
#if ELPP_VERBOSE_LOG
#   define UCVERBOSE(writer, dispatchAction, vlevel, ...) ELPP_WRITE_ULOG(writer, el::Level::Verbose, dispatchAction, vlevel, __VA_ARGS__)
#else
#   define UCVERBOSE(writer, dispatchAction, vlevel, ...) el::base::NullWriter()
#endif  // ELPP_VERBOSE_LOG

#define UCLOG(LEVEL, vlevel, ...) UC##LEVEL(el::base::Writer, el::base::DispatchAction::NormalLog, vlevel, __VA_ARGS__)

#define UVLOG(LEVEL, vlevel) UCLOG(LEVEL, vlevel, ELPP_CURR_FILE_LOGGER_ID, kLoggerId_User)
#define ULOG(LEVEL) UCLOG(LEVEL, 0, ELPP_CURR_FILE_LOGGER_ID, kLoggerId_User)
#define ULOG1(LEVEL) UCLOG(LEVEL, 1, ELPP_CURR_FILE_LOGGER_ID, kLoggerId_User)
#define ULOG2(LEVEL) UCLOG(LEVEL, 2, ELPP_CURR_FILE_LOGGER_ID, kLoggerId_User)

#endif //VIRGIL_CLI_LOGGER_H
