package main

import "html/template"

const (
	//SCOPE                 = "readonly"
	SCOPE                 = "https://www.googleapis.com/auth/photoslibrary.readonly"
	AUTH_CODE_DURATION    = 300
	ACCESS_TOKEN_DURATION = 3600
)

type Client struct {
	id          string
	name        string
	redirectURL string
	secret      string
}

type User struct {
	id       int
	name     string
	password string
}

type Session struct {
	client      string
	state       string
	scopes      string
	redirectUri string
}

type AuthCode struct {
	user         string
	clientId     string
	scopes       string
	redirect_uri string
	expires_at   int64
}

type TokenCode struct {
	user       string
	clientId   string
	scopes     string
	expires_at int64
}

type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
}

var templates = make(map[string]*template.Template)
var sessionList = make(map[string]Session)
var AuthCodeList = make(map[string]AuthCode)
var TokenCodeList = make(map[string]TokenCode)

// クライアント情報をハードコード
var clientInfo = Client{
	id:          "1234",
	name:        "test",
	redirectURL: "http://127.0.0.1:8080/callback",
	secret:      "secret",
}

// 登録ユーザをハードコード
var user = User{
	id:       1111,
	name:     "hoge",
	password: "password",
}
