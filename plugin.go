package traefik_jwt_eddsa

import (
	"context"
	"github.com/btcsuite/btcutil/base58"
	"github.com/golang-jwt/jwt/v5"
	"net/http"
	"strings"
)

// Config the plugin configuration.
type Config struct {
	PublicKey string `json:"public_key"`
	LoginURL  string `json:"login_url"`
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		PublicKey: "",
		LoginURL:  "http://localhost/login",
	}
}

// JwtEdDSA a plugin.
type JwtEdDSA struct {
	next   http.Handler
	name   string
	config *Config
}

// New created a new plugin.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	return &JwtEdDSA{
		config: config,
		name:   name,
		next:   next,
	}, nil
}

func (e *JwtEdDSA) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	authorization := req.Header.Values("Authorization")
	if len(authorization) < 1 {
		http.Redirect(rw, req, e.config.LoginURL, http.StatusFound)
	} else {
		tokenString := strings.TrimPrefix(authorization[0], "Bearer ")
		_, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			return base58.Decode(e.config.PublicKey), nil
		})
		if err != nil {
			http.Redirect(rw, req, e.config.LoginURL, http.StatusFound)
		}
	}
	e.next.ServeHTTP(rw, req)
}
