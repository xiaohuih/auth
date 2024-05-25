package provider

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/supabase/auth/internal/conf"
	"golang.org/x/oauth2"
)

const (
	defaultWechatAPIBase  = "api.weixin.qq.com"
	defaultWechatAuthBase = "open.weixin.qq.com"
)

// WechatProvider stores the custom config for wechat provider
type WechatProvider struct {
	*oauth2.Config
	APIPath string
}

type wechatUser struct {
	Name      string `json:"nickname"`
	AvatarURL string `json:"headimgurl"`
	ID        string `json:"unionid"`
}

// NewWechatProvider creates a Wechat account provider.
func NewWechatProvider(ext conf.OAuthProviderConfiguration, scopes string) (OAuthProvider, error) {
	if err := ext.ValidateOAuth(); err != nil {
		return nil, err
	}
	apiPath := chooseHost(ext.URL, defaultWechatAPIBase)
	authPath := chooseHost(ext.URL, defaultWechatAuthBase)

	oauthScopes := []string{
		"snsapi_login",
	}

	if scopes != "" {
		oauthScopes = append(oauthScopes, strings.Split(scopes, ",")...)
	}

	p := &WechatProvider{
		Config: &oauth2.Config{
			ClientID:     ext.ClientID[0],
			ClientSecret: ext.Secret,
			Endpoint: oauth2.Endpoint{
				AuthURL:  authPath + "/connect/qrconnect",
				TokenURL: apiPath + "/sns/oauth2/access_token",
			},
			Scopes:      oauthScopes,
			RedirectURL: ext.RedirectURI,
		},
		APIPath: apiPath,
	}
	return p, nil
}

// AuthCodeURL fetches the request token from the wechat provider
func (p *WechatProvider) AuthCodeURL(state string, args ...oauth2.AuthCodeOption) string {
	args = append(args, oauth2.SetAuthURLParam("appid", p.Config.ClientID))
	authURL := p.Config.AuthCodeURL(state, args...)
	if authURL != "" {
		if u, err := url.Parse(authURL); err != nil {
			u.RawQuery = strings.ReplaceAll(u.RawQuery, "+", "%20")
			authURL = u.String()
		}
	}
	return authURL
}

type tokenJSON struct {
	AccessToken  string         `json:"access_token"`
	RefreshToken string         `json:"refresh_token"`
	ExpiresIn    expirationTime `json:"expires_in"`
	OpenId       string         `json:"openid"`
	Scope        string         `json:"scope"`
}

func (e *tokenJSON) expiry() (t time.Time) {
	if v := e.ExpiresIn; v != 0 {
		return time.Now().Add(time.Duration(v) * time.Second)
	}
	return
}

type expirationTime int32

func (p WechatProvider) GetOAuthToken(code string) (*oauth2.Token, error) {
	v := url.Values{
		"appid":      {p.ClientID},
		"secret":     {p.ClientSecret},
		"grant_type": {"authorization_code"},
		"code":       {code},
	}
	if p.RedirectURL != "" {
		v.Set("redirect_uri", p.RedirectURL)
	}
	client := &http.Client{Timeout: defaultTimeout}
	req, err := http.NewRequest("POST", p.Endpoint.TokenURL, strings.NewReader(v.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	body, err := ioutil.ReadAll(io.LimitReader(r.Body, 1<<20))
	r.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("oauth2: cannot fetch token: %v", err)
	}
	if code := r.StatusCode; code < 200 || code > 299 {
		return nil, fmt.Errorf("oauth2: cannot fetch token: %v\nResponse: %s", r.Status, body)
	}

	var tj tokenJSON
	if err = json.Unmarshal(body, &tj); err != nil {
		return nil, err
	}
	token := &oauth2.Token{
		AccessToken:  tj.AccessToken,
		RefreshToken: tj.RefreshToken,
		Expiry:       tj.expiry(),
	}
	token = token.WithExtra(map[string]interface{}{
		"openid": tj.OpenId,
		"scope":  tj.Scope,
	})
	if token.AccessToken == "" {
		return nil, errors.New("oauth2: server response missing access_token")
	}
	return token, nil
}

func (p WechatProvider) GetUserData(ctx context.Context, tok *oauth2.Token) (*UserProvidedData, error) {
	openid, ok := tok.Extra("openid").(string)
	if !ok {
		return nil, errors.New("oauth2: server response missing openid")
	}
	v := url.Values{
		"openid":       {openid},
		"access_token": {tok.AccessToken},
	}
	client := &http.Client{Timeout: defaultTimeout}
	req, err := http.NewRequest("POST", p.APIPath+"/sns/userinfo", strings.NewReader(v.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	body, err := ioutil.ReadAll(io.LimitReader(r.Body, 1<<20))
	r.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("oauth2: cannot fetch token: %v", err)
	}
	if code := r.StatusCode; code < 200 || code > 299 {
		return nil, fmt.Errorf("oauth2: cannot fetch token: %v\nResponse: %s", r.Status, body)
	}

	var u wechatUser
	if err = json.Unmarshal(body, &u); err != nil {
		return nil, err
	}

	data := &UserProvidedData{
		Metadata: &Claims{
			Issuer:  p.APIPath,
			Subject: u.ID,
			Name:    u.Name,

			// To be deprecated
			AvatarURL:  u.AvatarURL,
			FullName:   u.Name,
			ProviderId: u.ID,
		},
	}

	return data, nil
}
