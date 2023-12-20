package traefik_jwt_eddsa

import (
	"context"
	"fmt"
	"github.com/btcsuite/btcutil/base58"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	amqp "github.com/rabbitmq/amqp091-go"
	"math/rand"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Config the plugin configuration.
type Config struct {
	PublicKey       string `json:"public_key"`
	LoginURL        string `json:"login_url"`
	AccessTokenName string `json:"access_token_name"`
	AmqpURL         string `json:"amqp_url"`
	AmqpExchange    string `json:"amqp_exchange"`
	AmqpRouting     string `json:"amqp_routing"`
	AmqpQueue       string `json:"amqp_queue"`
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{}
}

// JwtEdDSA a plugin.
type JwtEdDSA struct {
	ctx    context.Context
	next   http.Handler
	name   string
	amqp   *amqp.Channel
	config *Config
}

type Token struct {
	data  string
	added time.Time
}

var tokens map[string]*Token = make(map[string]*Token)

func handleAuthReplies(ctx context.Context, config *Config, channel *amqp.Channel) {
	msgs, err := channel.ConsumeWithContext(ctx,
		config.AmqpQueue,
		"Traefik",
		true,
		false,
		false,
		false,
		nil,
	)
	if err != nil {
		return
	}
	for msg := range msgs {
		body := string(msg.Body)
		parts := strings.Split(body, ":")
		tokens[parts[0]] = &Token{data: parts[1], added: time.Now()}
	}
}

func cleanUpTokens(ctx context.Context) {
	timer := time.NewTimer(2 * time.Minute)
	minusTenMinutes, _ := time.ParseDuration("-10m")
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			for connectionId, token := range tokens {
				if token.added.Before(time.Now().Add(minusTenMinutes)) {
					delete(tokens, connectionId)
				}
			}
		}
	}
}

// New created a new plugin.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if config.PublicKey == "" {
		return nil, fmt.Errorf("no public key provided")
	}

	var channel *amqp.Channel = nil
	connection, err := amqp.Dial(config.AmqpURL)
	if err != nil {
		defer connection.Close()
		channel, err = connection.Channel()
		if err != nil {
			return nil, err
		}
		defer channel.Close()

		go handleAuthReplies(ctx, config, channel)
		go cleanUpTokens(ctx)
	}

	return &JwtEdDSA{
		ctx:    ctx,
		config: config,
		name:   name,
		next:   next,
		amqp:   channel,
	}, nil
}

func (e *JwtEdDSA) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	connectionId, errConnectionId := req.Cookie("X-Connection-Id")
	xConnectionId := ""
	if errConnectionId != nil {
		value := req.RemoteAddr + req.Header.Get("X-Forwarded-For") + strconv.Itoa(rand.Int())
		cookie := &http.Cookie{
			Name:     "X-Connection-Id",
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
	rw.Header().Add("X-Connection-Id", xConnectionId)

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
		})
		if badToken != nil {
			if e.config.LoginURL != "" {
				http.Redirect(rw, req, e.config.LoginURL, http.StatusFound)
			} else {
				http.Error(rw, "Forbidden", http.StatusForbidden)
			}
		} else {
			// Maybe it is needed to update the token
			expirationTime, err := token.Claims.GetExpirationTime()
			if err != nil {
				http.Error(rw, "Can't find JWT expiration time", http.StatusInternalServerError)
			} else {
				// Already got response from auth service?
				if tokens[xConnectionId] != nil {
					newAuth := authorization
					newAuth.Value = tokens[xConnectionId].data
					tokenString = tokens[xConnectionId].data
					delete(tokens, xConnectionId)
					http.SetCookie(rw, newAuth)
				} else {
					// Ask auth service for a new token
					minusOneHour, _ := time.ParseDuration("-1h")
					if expirationTime.After(time.Now().Add(minusOneHour)) && xConnectionId != "" && e.amqp != nil {
						e.amqp.PublishWithContext(
							e.ctx,
							e.config.AmqpExchange,
							e.config.AmqpRouting,
							false,
							false,
							amqp.Publishing{
								ContentType: "text/plain",
								Body:        []byte(xConnectionId + ":" + tokenString),
							},
						)
					}
				}
			}
			rw.Header().Add("Authorization", "Bearer "+tokenString)
		}
	}
	e.next.ServeHTTP(rw, req)
}
