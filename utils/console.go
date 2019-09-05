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
	"bufio"
	"fmt"
	"gopkg.in/urfave/cli.v2"
	"io/ioutil"
	"os"
	"strings"
)

var scanner = bufio.NewScanner(os.Stdin)

func ReadKeyStringFromFile(context *cli.Context, fileName string) (string, error) {
	value := ""
	f, err := os.Open(fileName)
	if err != nil {
		return "", err
	}
	defer func() {
		if err := f.Close(); err != nil {
			panic(err)
		}
	}()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		t := scanner.Text()
		if strings.Contains(t, "BEGIN ") {
			continue
		}
		value = t
		break
	}
	return value, nil
}

func ReadFileFlagOrParamOrFromConsole(context *cli.Context, flag, paramName, paramDescription string) ([]byte, error) {

	inputFileName := ReadFlagOrDefault(context, flag, "")
	if inputFileName == "" {
		return []byte(ReadParamOrDefaultOrFromConsole(context, paramName, paramDescription, "")), nil
	}
	return ioutil.ReadFile(inputFileName)
}

func ReadParamOrDefaultOrFromConsole(context *cli.Context, paramName, paramDescription, defaultValue string) string {
	value := strings.Join(context.Args().Slice(), " ")
	if value != "" {
		if len(value) < 3 {
			fmt.Printf("%s length can't be less than 3\n", paramName)
		} else {
			return value
		}
	}
	if defaultValue != "" {
		return defaultValue
	}
	return ReadConsoleValue(paramName, paramDescription)
}

func ReadConsoleValue(paramName, paramDescription string, options ...string) string {

	fmt.Printf("%s:\n", paramDescription)

	value := ""
	valueSet := false
	for !valueSet {
		scanner.Scan()
		value = scanner.Text()
		if len(options) == 0 {
			if len(value) < 3 {
				fmt.Printf("%s length can't be less than 3\n", paramName)
				fmt.Printf("%s:\n", paramDescription)
			} else {
				valueSet = true
			}
		} else {
			if !contains(options, value) {
				fmt.Printf("invalid %s value\n", paramName)
				fmt.Printf("%s:\n", paramDescription)
			} else {
				valueSet = true
			}
		}
	}
	return value
}

func contains(array []string, value string) bool {
	for _, s := range array {
		if s == value {
			return true
		}
	}
	return false
}

func ReadFlagOrDefault(context *cli.Context, flagName, defaultValue string) string {
	value := context.String(flagName)
	if value != "" {
		return value
	}
	return defaultValue
}

func ReadFlagOrConsoleValue(context *cli.Context, flagName, paramDescription string, options ...string) string {
	value := context.String(flagName)
	if value != "" {
		if len(options) == 0 {
			return value
		}
		if contains(options, value) {
			return value
		}
		fmt.Printf("incorrect flag %s value\n", flagName)

	}
	return ReadConsoleValue(flagName, paramDescription, options...)
}
