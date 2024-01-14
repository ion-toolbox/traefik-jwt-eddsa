// yaegi:tags purego

package traefik_jwt_eddsa

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/btcsuite/btcutil/base58"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"math/rand"
	"net/http"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Config the plugin configuration.
type Config struct {
	PublicKey       string `json:"public_key"`
	LoginURL        string `json:"login_url"`
	AccessTokenName string `json:"access_token_name"`
	ParseCookies    bool   `json:"parse_cookies"`
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{}
}

// JwtEdDSA a plugin.
type JwtEdDSA struct {
	next   http.Handler
	name   string
	config *Config
}

// New created a new plugin.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if config.PublicKey == "" {
		return nil, fmt.Errorf("no public key provided")
	}
	if config.AccessTokenName == "" {
		return nil, fmt.Errorf("no access token name provided")
	}

	return &JwtEdDSA{
		config: config,
		name:   name,
		next:   next,
	}, nil
}

func (e *JwtEdDSA) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	connectionId, errConnectionId := req.Cookie("X-Ray-Id")
	xConnectionId := ""
	if errConnectionId != nil {
		value := req.RemoteAddr + req.Header.Get("X-Forwarded-For") + strconv.Itoa(rand.Int())
		cookie := &http.Cookie{
			Name:     "X-Ray-Id",
			Value:    uuid.NewSHA1(uuid.NameSpaceURL, []byte(value)).String(),
			Path:     "/",
			Expires:  time.Time{},
			Secure:   false,
			HttpOnly: true,
		}
		xConnectionId = cookie.Value
		http.SetCookie(rw, cookie)
	} else {
		xConnectionId = connectionId.Value
	}
	rw.Header().Add("X-Ray-Id", xConnectionId)

	authorization, noAccessToken := req.Cookie(e.config.AccessTokenName)
	if noAccessToken != nil {
		if e.config.LoginURL != "" {
			http.Redirect(rw, req, e.config.LoginURL, http.StatusFound)
		} else {
			http.Error(rw, "Forbidden", http.StatusForbidden)
		}
	} else {
		tokenString := authorization.Value
		token, badToken := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return base58.Decode(e.config.PublicKey), nil
		}, jwt.WithoutClaimsValidation())
		if badToken != nil {
			if e.config.LoginURL != "" {
				http.Redirect(rw, req, e.config.LoginURL, http.StatusFound)
			} else {
				http.Error(rw, "Forbidden", http.StatusForbidden)
			}
		} else {
			if e.config.ParseCookies {
				for k, _ := range req.Header {
					if strings.HasPrefix("x-jwt", k) {
						req.Header.Del(k)
					}
				}
				firstLetterIsNotCapital := regexp.MustCompile("^[^A-Z]")
				for k, v := range token.Claims.(jwt.MapClaims) {
					header := "x-jwt"
					if firstLetterIsNotCapital.MatchString(e.config.AccessTokenName) {
						header += "-"
					}
					header += regexp.MustCompile("([A-Z][^A-Z])").ReplaceAllString(e.config.AccessTokenName, "-$1")
					if firstLetterIsNotCapital.MatchString(k) {
						header += "-"
					}
					header += regexp.MustCompile("([A-Z][^A-Z])").ReplaceAllString(k, "-$1")
					if reflect.TypeOf(v).Kind() != reflect.String {
						bytes, err := json.Marshal(v)
						if err != nil {
							return
						}
						req.Header.Add(header, string(bytes))
					} else {
						req.Header.Add(header, v.(string))
					}

				}
			}
			req.Header.Add("Authorization", "Bearer "+tokenString)
		}
	}
	e.next.ServeHTTP(rw, req)
}
