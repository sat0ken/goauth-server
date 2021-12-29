package main

import (
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"html/template"
	"log"
	"net/http"
	"time"
)

// 3.1.  認可エンドポイント
func auth(w http.ResponseWriter, req *http.Request) {
	query := req.URL.Query()
	requiredParameter := []string{"response_type", "client_id", "redirect_uri"}
	// 必須パラメータのチェック
	for _, v := range requiredParameter {
		if !query.Has(v) {
			log.Printf("%s is missing", v)
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(fmt.Sprintf("invalid_request. %s is missing", v)))
			return
		}
	}
	// client id の一致確認
	if clientInfo.id != query.Get("client_id") {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("client_id is not match"))
		return
	}
	// レスポンスタイプはいったん認可コードだけにしておく
	if "code" != query.Get("response_type") {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("only support code"))
		return
	}
	sessionId := uuid.New().String()
	// セッション情報を保存しておく
	session := Session{
		client:      query.Get("client_id"),
		state:       query.Get("state"),
		scopes:      query.Get("scope"),
		redirectUri: query.Get("redirect_uri"),
	}
	sessionList[sessionId] = session

	cookie := &http.Cookie{
		Name:  "session",
		Value: sessionId,
	}
	http.SetCookie(w, cookie)

	// ログイン&権限認可の画面を戻す
	if err := templates["login"].Execute(w, struct {
		ClientId string
		Scope    string
	}{
		ClientId: session.client,
		Scope:    session.scopes,
	}); err != nil {
		log.Println(err)
	}
	log.Println("return login page...")

}

// 認可レスポンスを返す
func authCheck(w http.ResponseWriter, req *http.Request) {

	loginUser := req.FormValue("username")
	password := req.FormValue("password")

	if loginUser != user.name || password != user.password {
		w.Write([]byte("login failed"))
	} else {

		cookie, _ := req.Cookie("session")
		v, _ := sessionList[cookie.Value]

		authCodeString := uuid.New().String()
		authData := AuthCode{
			user:         loginUser,
			clientId:     v.client,
			scopes:       v.scopes,
			redirect_uri: authCodeString,
			expires_at:   time.Now().Unix() + 300,
		}
		// 認可コードを保存
		AuthCodeList[authCodeString] = authData

		location := fmt.Sprintf("%s?code=%s&state=%s", v.redirectUri, authCodeString, v.state)
		log.Printf("location url : %s", location)
		w.Header().Add("Location", location)
		w.WriteHeader(302)

	}

}

// トークンを発行するエンドポイント
func token(w http.ResponseWriter, req *http.Request) {
	req.ParseForm()
	query := req.Form
	requiredParameter := []string{"grant_type", "code", "client_id", "redirect_uri"}
	// 必須パラメータのチェック
	for _, v := range requiredParameter {
		if !query.Has(v) {
			log.Printf("%s is missing", v)
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte(fmt.Sprintf("invalid_request. %s is missing\n", v)))
			return
		}
	}

	// 認可コードフローだけサポート
	if "authorization_code" != query.Get("grant_type") {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(fmt.Sprintf("invalid_request. not support type.\n")))
	}

	// 保存していた認可コードのデータを取得。なければエラーを返す
	v, ok := AuthCodeList[query.Get("code")]
	//log.Printf("authcode is %s\n", ok)
	if !ok {
		log.Println("auth code isn't exist")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(fmt.Sprintf("no authrization code")))
	}

	// 認可リクエスト時のクライアントIDと比較
	if v.clientId != query.Get("client_id") {
		log.Println("client_id not match")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(fmt.Sprintf("invalid_request. client_id not match.\n")))
	}

	// 認可コードの有効期限を確認
	if v.expires_at < time.Now().Unix() {
		log.Println("authcode expire")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(fmt.Sprintf("invalid_request. auth code time limit is expire.\n")))
	}

	// clientシークレットの確認
	if clientInfo.secret != query.Get("client_secret") {
		log.Println("client_secret is not match.")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(fmt.Sprintf("invalid_request. client_secret is not match.\n")))
	}

	tokenString := uuid.New().String()
	expireTime := time.Now().Unix() + ACCESS_TOKEN_DURATION
	tokenInfo := TokenCode{
		user:       v.user,
		clientId:   v.clientId,
		scopes:     v.scopes,
		expires_at: expireTime,
	}
	TokenCodeList[tokenString] = tokenInfo
	// 認可コードを削除
	delete(AuthCodeList, query.Get("code"))

	tokenResp := TokenResponse{
		AccessToken: tokenString,
		TokenType:   "Bearer",
		ExpiresIn:   expireTime,
	}
	resp, err := json.Marshal(tokenResp)
	if err != nil {
		log.Println("json marshal err")
	}

	log.Printf("token ok to client %s, token is %s", v.clientId, string(resp))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(resp)

}

// http://openid-foundation-japan.github.io/rfc6749.ja.html
func main() {
	var err error
	templates["login"], err = template.ParseFiles("login.html")
	if err != nil {
		log.Fatal(err)
	}
	log.Println("start oauth server on localhost:8081...")
	http.HandleFunc("/auth", auth)
	http.HandleFunc("/authcheck", authCheck)
	http.HandleFunc("/token", token)
	err = http.ListenAndServe("localhost:8081", nil)
	if err != nil {
		log.Fatal(err)
	}

}
