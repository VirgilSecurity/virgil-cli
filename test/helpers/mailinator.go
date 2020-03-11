package helpers

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"regexp"

	"github.com/pkg/errors"
)

const (
	MailinatorApi      = "https://api.mailinator.com/api/"
	ConfirmCodePattern = "href=\"https://dashboard(-.{3})?.virgilsecurity.com/api/auth/register/confirm/(.*)\""
)

type MailinatorMessageInfo struct {
	Subject    string `json:"subject"`
	ID         string `json:"id"`
	SecondsAgo int    `json:"seconds_ago"`
}

type MailinatorMessagePart struct {
	Body string `json:"body"`
}

type MessageData struct {
	Data MailinatorMessage `json:"data"`
}

type MailinatorMessage struct {
	Parts []MailinatorMessagePart `json:"parts"`
}

type MailinatorInboxResponse struct {
	Messages []MailinatorMessageInfo `json:"messages"`
}

func GetConfirmCode(email string) string {
	messageText, err := loadMailinatorMessage(email)
	re := regexp.MustCompile(ConfirmCodePattern)
	res := re.FindAllStringSubmatch(messageText, -1)
	if err != nil {
		fmt.Printf("mailinator error: %+v", err)
	}
	confCode := res[0][2]
	return confCode
}

func loadMailinatorMessage(email string) (msg string, err error) {
	mailinatorToken := os.Getenv("MAILINATOR_TOKEN")
	if mailinatorToken == "" {
		fmt.Println("WARNING! Mailinator token not set!")
	}

	resp, err := http.Get(fmt.Sprintf(MailinatorApi+"inbox?token=%s&to=%s", mailinatorToken, email))
	if err != nil {
		return "", errors.WithMessage(err, "loadMailinatorMessage Get inbox failed: ")
	}

	if resp != nil {
		defer resp.Body.Close()
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	var mailinatorMessageList MailinatorInboxResponse
	err = json.Unmarshal(body, &mailinatorMessageList)
	if err != nil {
		return "", errors.WithMessage(err, "loadMailinatorMessage json mailinator unmarshal inbox failed: ")
	}

	if len(mailinatorMessageList.Messages) == 0 {
		return "", errors.New("mailinator inbox empty")
	}

	if len(mailinatorMessageList.Messages) > 1 {
		return "", errors.New("mailinator inbox to few mails")
	}

	messageID := mailinatorMessageList.Messages[0].ID
	resp, err = http.Get(fmt.Sprintf(MailinatorApi+"message?token=%s&id=%s", mailinatorToken, messageID))
	if err != nil {
		return "", errors.WithMessage(err, "loadMailinatorMessage Get message failed: ")
	}

	if resp != nil {
		defer resp.Body.Close()
	}

	body, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", errors.WithMessage(err, "loadMailinatorMessage read message body failed: ")
	}

	var message MessageData
	err = json.Unmarshal(body, &message)
	if err != nil {
		return "", errors.WithMessage(err, "loadMailinatorMessage json mailinator unmarshal message failed: ")
	}

	return message.Data.Parts[0].Body, nil
}
