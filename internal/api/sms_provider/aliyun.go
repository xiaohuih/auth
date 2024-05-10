package sms_provider

import (
	"fmt"

	"github.com/supabase/auth/internal/conf"

	openapi "github.com/alibabacloud-go/darabonba-openapi/v2/client"
	dysmsapi20170525 "github.com/alibabacloud-go/dysmsapi-20170525/v3/client"
	"github.com/alibabacloud-go/tea/tea"
)

const (
	defaultAliyunEndpoint = "dysmsapi.aliyuncs.com"
)

type AliyunProvider struct {
	Config *conf.AliyunProviderConfiguration
}

type AliyunError struct {
	Code        int    `json:"code"`
	Description string `json:"description"`
	Parameter   string `json:"parameter"`
}

type AliyunErrResponse struct {
	Errors []AliyunError `json:"errors"`
}

func (t AliyunErrResponse) Error() string {
	return t.Errors[0].Description
}

// Creates a SmsProvider with the Aliyun Config
func NewAliyunProvider(config conf.AliyunProviderConfiguration) (SmsProvider, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	if config.Endpoints == "" {
		config.Endpoints = defaultAliyunEndpoint
	}

	return &AliyunProvider{
		Config: &config,
	}, nil
}

func (t *AliyunProvider) SendMessage(phone, message, channel, otp string) (string, error) {
	switch channel {
	case SMSProvider:
		return t.SendSms(phone, message, otp)
	default:
		return "", fmt.Errorf("channel type %q is not supported for Aliyun", channel)
	}
}

// Send an SMS containing the OTP with Aliyun's API
func (t *AliyunProvider) SendSms(phone string, message string, opt string) (string, error) {
	apiConfig := &openapi.Config{
		AccessKeyId:     tea.String(t.Config.ApiKey),
		AccessKeySecret: tea.String(t.Config.ApiSecret),
		Endpoint:        tea.String("dysmsapi.aliyuncs.com"),
	}
	if t.Config.Endpoints != "" {
		apiConfig.Endpoint = tea.String(t.Config.Endpoints)
	}

	request := &dysmsapi20170525.SendSmsRequest{
		PhoneNumbers:  tea.String(phone),
		SignName:      tea.String(t.Config.SignName),
		TemplateCode:  tea.String(message),
		TemplateParam: tea.String(fmt.Sprintf(`{"code":"%s"}`, opt)),
	}
	client, err := dysmsapi20170525.NewClient(apiConfig)
	if err != nil {
		return "", err
	}

	resp, err := client.SendSms(request)
	if err != nil {
		return "", err
	}

	return *resp.Body.RequestId, nil
}
