package utils

import (
	"bufio"
	"fmt"
	"gopkg.in/urfave/cli.v2"
	"os"
	"strings"
)

var scanner = bufio.NewScanner(os.Stdin)

func ReadParamOrDefaultOrFromConsole(context *cli.Context, paramName, paramDescription, defaultValue string) string {
	value := strings.Join(context.Args().Slice(), " ")
	if value != "" {
		return value
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
			if value == "" {
				fmt.Printf("%s can't be empty\n", paramName)
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
