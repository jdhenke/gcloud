package gcloud

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"time"

	"github.com/gorilla/sessions"
	"golang.org/x/oauth2"
)

type contextKey string

const (
	sessionKey  contextKey = "email"
	sessionName            = "gcloudAuthSession"
)

func NewAuthorizer(clientID, clientSecret, redirectURL string, cookieStoreKeyPairs [][]byte) *Authorizer {
	conf := oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Endpoint: oauth2.Endpoint{
			AuthURL:   "https://accounts.google.com/o/oauth2/auth",
			TokenURL:  "https://oauth2.googleapis.com/token",
			AuthStyle: oauth2.AuthStyleInParams,
		},
		RedirectURL: redirectURL,
		Scopes:      []string{"https://www.googleapis.com/auth/userinfo.email"},
	}
	_ = conf
	return &Authorizer{
		conf:  conf,
		store: sessions.NewCookieStore(cookieStoreKeyPairs...),
	}
}

type Authorizer struct {
	conf  oauth2.Config
	store sessions.Store
}

func (a *Authorizer) HandleRedirect(rw http.ResponseWriter, r *http.Request) {
	c, _ := r.Cookie("oauthstate")
	if c.Value != r.FormValue("state") {
		http.Error(rw, "invalid oauth state", 400)
		return
	}
	http.SetCookie(rw, &http.Cookie{
		Name:   "oauthstate",
		MaxAge: -1,
	})
	token, err := a.conf.Exchange(r.Context(), r.FormValue("code"))
	if err != nil {
		log.Printf("error exchanging code for token: %v", err)
		http.Error(rw, http.StatusText(500), 500)
		return
	}
	const oauthGoogleURLAPI = "https://www.googleapis.com/oauth2/v2/userinfo?access_token="
	response, err := http.Get(oauthGoogleURLAPI + token.AccessToken)
	if err != nil {
		log.Printf("error getting google user info: %v", err)
		http.Error(rw, http.StatusText(500), 500)
		return
	}
	defer func() {
		_, _ = ioutil.ReadAll(response.Body)
		_ = response.Body.Close()
	}()
	var info struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(response.Body).Decode(&info); err != nil {
		log.Printf("error decoding user info: %v", err)
		http.Error(rw, http.StatusText(500), 500)
		return
	}

	sess, _ := a.store.Get(r, sessionName)
	sess.Values["email"] = info.Email
	path := "/"
	if r := sess.Values["redirect"]; r != nil {
		path = r.(string)
	}
	delete(sess.Values, "redirect")
	_ = sess.Save(r, rw)

	http.Redirect(rw, r, path, http.StatusTemporaryRedirect)
}

func (a *Authorizer) HandleLogin(rw http.ResponseWriter, r *http.Request) {
	var expiration = time.Now().Add(20 * time.Minute)
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	state := base64.URLEncoding.EncodeToString(b)
	cookie := http.Cookie{Name: "oauthstate", Value: state, Expires: expiration}
	http.SetCookie(rw, &cookie)
	u := a.conf.AuthCodeURL(state)
	http.Redirect(rw, r, u, http.StatusTemporaryRedirect)
}

func (a *Authorizer) HandleLogout(rw http.ResponseWriter, r *http.Request) {
	sess, _ := a.store.Get(r, sessionName)
	sess.Options.MaxAge = -1
	_ = sess.Save(r, rw)
	http.Redirect(rw, r, "/login", http.StatusSeeOther)
}

func (a *Authorizer) RequireAuth(h http.Handler) http.Handler {
	return http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		sess, _ := a.store.Get(r, sessionName)
		emailObj := sess.Values["email"]
		if emailObj == nil {
			sess.Values["redirect"] = r.URL.Path
			_ = sess.Save(r, rw)
			http.Redirect(rw, r, "/login", http.StatusTemporaryRedirect)
			return
		}
		email := emailObj.(string)
		r = r.WithContext(context.WithValue(r.Context(), sessionKey, Session{
			Email: email,
		}))
		h.ServeHTTP(rw, r)
	})
}

type Session struct {
	Email string
}

func (a *Authorizer) GetSession(ctx context.Context) Session {
	return ctx.Value(sessionKey).(Session)
}
