package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"html/template"
	"log"
	"net/http"
	"strings"
	"time"
)

// https://auth0.com/docs/authorization/flows/call-your-api-using-the-authorization-code-flow-with-pkce#javascript-sample
func base64URLEncode(verifier string) string {
	hash := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

// 3.1.  認可エンドポイント
func auth(w http.ResponseWriter, req *http.Request) {

	query := req.URL.Query()
	session := Session{
		client:      query.Get("client_id"),
		state:       query.Get("state"),
		scopes:      query.Get("scope"),
		redirectUri: query.Get("redirect_uri"),
	}

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
	// レスポンスタイプはいったん認可コードだけをサポート
	if "code" != query.Get("response_type") {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("only support code"))
		return
	}

	// scopeの確認、OAuthかOIDCか
	// 組み合わせへの対応は面倒なので "openid profile" で固定
	if "openid profile" == query.Get("scope") {
		session.oidc = true
	} else {
		session.code_challenge = query.Get("code_challenge")
		session.code_challenge_method = query.Get("code_challenge_method")
	}

	// セッションIDを生成
	sessionId := uuid.New().String()
	// セッション情報を保存しておく
	sessionList[sessionId] = session

	// CookieにセッションIDをセット
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
		http.SetCookie(w, cookie)
		v, _ := sessionList[cookie.Value]

		authCodeString := uuid.New().String()
		authData := AuthCode{
			user:         loginUser,
			clientId:     v.client,
			scopes:       v.scopes,
			redirect_uri: v.redirectUri,
			expires_at:   time.Now().Unix() + 300,
		}
		// 認可コードを保存
		AuthCodeList[authCodeString] = authData

		log.Printf("auth code accepet : %s\n", authData)

		location := fmt.Sprintf("%s?code=%s&state=%s", v.redirectUri, authCodeString, v.state)
		w.Header().Add("Location", location)
		w.WriteHeader(302)

	}

}

// トークンを発行するエンドポイント
func token(w http.ResponseWriter, req *http.Request) {

	cookie, _ := req.Cookie("session")
	req.ParseForm()
	query := req.Form
	session := sessionList[cookie.Value]

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
		return
	}

	// 保存していた認可コードのデータを取得。なければエラーを返す
	v, ok := AuthCodeList[query.Get("code")]
	if !ok {
		log.Println("auth code isn't exist")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(fmt.Sprintf("no authrization code")))
		return
	}

	// 認可リクエスト時のクライアントIDと比較
	if v.clientId != query.Get("client_id") {
		log.Println("client_id not match")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(fmt.Sprintf("invalid_request. client_id not match.\n")))
		return
	}

	// 認可リクエスト時のリダイレクトURIと比較
	if v.redirect_uri != query.Get("redirect_uri") {
		log.Println("redirect_uri not match")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(fmt.Sprintf("invalid_request. redirect_uri not match.\n")))
		return
	}

	// 認可コードの有効期限を確認
	if v.expires_at < time.Now().Unix() {
		log.Println("authcode expire")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(fmt.Sprintf("invalid_request. auth code time limit is expire.\n")))
		return
	}

	// clientシークレットの確認
	if clientInfo.secret != query.Get("client_secret") {
		log.Println("client_secret is not match.")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(fmt.Sprintf("invalid_request. client_secret is not match.\n")))
		return
	}

	// PKCEのチェック
	// clientから送られてきたverifyをsh256で計算&base64urlエンコードしてから
	// 認可リクエスト時に送られてきてセッションに保存しておいたchallengeと一致するか確認
	if session.oidc == false && session.code_challenge != base64URLEncode(query.Get("code_verifier")) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("PKCE check is err..."))
		return
	}

	tokenString := uuid.New().String()
	expireTime := time.Now().Unix() + ACCESS_TOKEN_DURATION

	tokenInfo := TokenCode{
		user:       v.user,
		clientId:   v.clientId,
		scopes:     v.scopes,
		expires_at: expireTime,
	}
	// 払い出したトークン情報を保存
	TokenCodeList[tokenString] = tokenInfo
	// 認可コードを削除
	delete(AuthCodeList, query.Get("code"))

	tokenResp := TokenResponse{
		AccessToken: tokenString,
		TokenType:   "Bearer",
		ExpiresIn:   expireTime,
	}
	if session.oidc {
		tokenResp.IdToken, _ = makeJWT()
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

func certs(w http.ResponseWriter, req *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write(makeJWK())
}

func userinfo(w http.ResponseWriter, req *http.Request) {
	h := req.Header.Get("Authorization")
	tmp := strings.Split(h, " ")

	// トークンがあるか確認
	v, ok := TokenCodeList[tmp[1]]
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(fmt.Sprintf("token is wrong.\n")))
		return
	}

	// トークンの有効期限が切れてないか
	if v.expires_at < time.Now().Unix() {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(fmt.Sprintf("token is expire.\n")))
		return
	}

	// スコープが正しいか、openid profileで固定
	if v.scopes != "openid profile" {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(fmt.Sprintf("scope is not permit.\n")))
		return
	}

	// ユーザ情報を返す
	var m = map[string]interface{}{
		"sub":         user.sub,
		"name":        user.name_ja,
		"given_name":  user.given_name,
		"family_name": user.family_name,
		"locale":      user.locale,
	}
	buf, _ := json.MarshalIndent(m, "", "  ")
	w.WriteHeader(http.StatusOK)
	w.Write(buf)
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
	http.HandleFunc("/certs", certs)
	http.HandleFunc("/userinfo", userinfo)
	err = http.ListenAndServe("localhost:8081", nil)
	if err != nil {
		log.Fatal(err)
	}

}
