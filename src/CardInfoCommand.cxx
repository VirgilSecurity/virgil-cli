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

#include <cli/command/CardInfoCommand.h>

#include <cli/api/api.h>
#include <cli/crypto/Crypto.h>
#include <cli/io/Logger.h>
#include <cli/error/ArgumentError.h>
#include <cli/model/CardProperty.h>
#include <cli/formatter/CardFormatter.h>
#include <cli/formatter/CardRawFormatter.h>
#include <cli/formatter/CardKeyValueFormatter.h>

#include <cli/memory.h>

using cli::Crypto;
using cli::command::CardInfoCommand;
using cli::argument::ArgumentIO;
using cli::argument::ArgumentImportance;
using cli::argument::ArgumentParseOptions;
using cli::error::ArgumentRuntimeError;
using cli::error::ArgumentLogicError;
using cli::model::CardProperty;
using cli::formatter::CardFormatter;
using cli::formatter::CardRawFormatter;
using cli::formatter::CardKeyValueFormatter;

const char* CardInfoCommand::doGetName() const {
    return arg::value::VIRGIL_COMMAND_CARD_INFO;
}

const char* CardInfoCommand::doGetUsage() const {
    return usage::VIRGIL_CARD_INFO;
}

ArgumentParseOptions CardInfoCommand::doGetArgumentParseOptions() const {
    return ArgumentParseOptions().disableOptionsFirst();
}

static std::unique_ptr<CardFormatter> define_formatter(size_t infoOptionsCount) {
    if (infoOptionsCount == 1) {
        // Only one Virgil Card property will be shown, so print it as is.
        return std::make_unique<CardRawFormatter>();
    } else {
        // Multiple Virgil Card properties will be shown as formatted keys and values.
        return std::make_unique<CardKeyValueFormatter>();
    }
}

static CardProperty property_from(const std::string& format) {
    if (format == cli::arg::value::VIRGIL_CARD_INFO_OUTPUT_FORMAT_ID) {
        return CardProperty::Identifier;
    } else if (format == cli::arg::value::VIRGIL_CARD_INFO_OUTPUT_FORMAT_IDENTITY) {
        return CardProperty::Identity;
    } else if (format == cli::arg::value::VIRGIL_CARD_INFO_OUTPUT_FORMAT_IDENTITY_TYPE) {
        return CardProperty::IdentityType;
    } else if (format == cli::arg::value::VIRGIL_CARD_INFO_OUTPUT_FORMAT_PUBLIC_KEY) {
        return CardProperty::PublicKey;
    } else if (format == cli::arg::value::VIRGIL_CARD_INFO_OUTPUT_FORMAT_SCOPE) {
        return CardProperty::Scope;
    } else if (format == cli::arg::value::VIRGIL_CARD_INFO_OUTPUT_FORMAT_VERSION) {
        return CardProperty::Version;
    } else if (format == cli::arg::value::VIRGIL_CARD_INFO_OUTPUT_FORMAT_INFO) {
        return CardProperty::Info;
    } else if (format == cli::arg::value::VIRGIL_CARD_INFO_OUTPUT_FORMAT_DATA) {
        return CardProperty::Data;
    } else if (format == cli::arg::value::VIRGIL_CARD_INFO_OUTPUT_FORMAT_SIGNATURES) {
        return CardProperty::Signatures;
    } else {
        throw ArgumentLogicError(
                tfm::format("Unexpected Virgil Card format: '%s'. Validation MUST failed first.", format));
    }
}

static void configure_formatter(CardFormatter& cardFormatter, const std::vector<std::string>& cardOutputFormat) {
    for (const auto& outputFormat : cardOutputFormat) {
        cardFormatter.showProperty(property_from(outputFormat));
    }
}

void CardInfoCommand::doProcess() const {
    ULOG1(INFO) << "Read arguments.";
    const auto cardList = getArgumentIO()->getCardListFromInput(ArgumentImportance::Optional);
    const auto cardOutputFormat = getArgumentIO()->getCardOutputFormat(ArgumentImportance::Required);
    auto output = getArgumentIO()->getOutputSink(ArgumentImportance::Optional);

    ULOG1(INFO) << "Define Virgil Card formatter.";
    auto formatter = define_formatter(cardOutputFormat.size());

    ULOG1(INFO) << "Configure Virgil Card formatter";
    configure_formatter(*formatter, cardOutputFormat);

    for (const auto& card : cardList) {
        ULOG1(INFO) << tfm::format("Process Virgil Card: %s:%s (%s).",
                card.identityType(), card.identity(), card.identifier());
        auto cardInfo = formatter->format(card);
        ULOG1(INFO) << "Write card info to the output.";
        output.write(cardInfo);
    }
}
