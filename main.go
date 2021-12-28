package main

import (
	"html/template"
	"log"
	"net/http"
)

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

var templates = make(map[string]*template.Template)

var SessionInfo []Session

// クライアント情報をハードコード
var clientInfo = Client{
	id:          "1234",
	name:        "test",
	redirectURL: "http://127.0.0.1:8080/callback",
}

//登録ユーザをハードコード
var user = User{
	id:       1111,
	name:     "hoge",
	password: "password",
}

// 3.1.  認可エンドポイント
func auth(w http.ResponseWriter, req *http.Request) {
	query := req.URL.Query()

	requiredParameter := []string{"response_type", "client_id", "redirect_uri"}
	// 必須パラメータのチェック
	for _, v := range requiredParameter {
		if !query.Has(v) {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
	}
	// client id の一致確認
	if clientInfo.id != query.Get("client_id") {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	// レスポンスタイプはいったん認可コードだけにしておく
	if "code" != query.Get("response_type") {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	session := Session{
		client:      query.Get("client_id"),
		state:       query.Get("state"),
		scopes:      query.Get("scope"),
		redirectUri: query.Get("redirect_uri"),
	}
	SessionInfo = append(SessionInfo, session)

	if err := templates["login"].Execute(w, struct {
		ClientId string
		Scope    string
	}{
		ClientId: session.client,
		Scope:    session.scopes,
	}); err != nil {
		log.Println(err)
	}
}

// トークンを発行するエンドポイント
func token(w http.ResponseWriter, req *http.Request) {

}

// http://openid-foundation-japan.github.io/rfc6749.ja.html
func main() {
	var err error
	templates["login"], err = template.ParseFiles("login.html")
	if err != nil {
		log.Fatal(err)
	}
	log.Println("start oauth server on localhost:8080...")
	http.HandleFunc("/auth", auth)
	http.HandleFunc("/token", token)
	err = http.ListenAndServe(":8081", nil)
	if err != nil {
		log.Fatal(err)
	}

}
