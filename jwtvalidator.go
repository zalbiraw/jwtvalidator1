// Package jwtvalidator is a plugin to validate JWTs and forward claims to headers and query parameters.
package jwtvalidator

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v4"
)

// Config the plugin configuration.
type Config struct {
	AuthHeader         string            `json:"authHeader,omitempty" yaml:"authHeader,omitempty"`
	ForwardHeaders     map[string]string `json:"forwardHeaders,omitempty" yaml:"forwardHeaders,omitempty"`
	ForwardQueryParams map[string]string `json:"forwardQueryParams,omitempty" yaml:"forwardQueryParams,omitempty"`
	SigningSecret      string            `json:"signingSecret" yaml:"signingSecret"`
	TokenPrefix        string            `json:"tokenPrefix,omitempty" yaml:"tokenPrefix,omitempty"`
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		AuthHeader:         "Authorization",
		ForwardHeaders:     make(map[string]string),
		ForwardQueryParams: make(map[string]string),
		TokenPrefix:        "Bearer ",
	}
}

// JWTValidator validates JWT tokens and forwards claims to headers and query parameters.
type JWTValidator struct {
	authHeader         string
	forwardHeaders     map[string]string
	forwardQueryParams map[string]string
	name               string
	next               http.Handler
	signingSecret      string
	tokenPrefix        string
}

// New creates a new JWTValidator handler.
func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if config.SigningSecret == "" {
		return nil, errors.New("signingSecret cannot be empty")
	}
	if config.AuthHeader == "" {
		config.AuthHeader = "Authorization"
	}
	return &JWTValidator{
		authHeader:         config.AuthHeader,
		forwardHeaders:     config.ForwardHeaders,
		forwardQueryParams: config.ForwardQueryParams,
		name:               name,
		next:               next,
		signingSecret:      config.SigningSecret,
		tokenPrefix:        config.TokenPrefix,
	}, nil
}

func (p *JWTValidator) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	if !p.checkAndWriteInvalidPrefix(rw, r) {
		return
	}
	tokenString := strings.TrimPrefix(r.Header.Get(p.authHeader), p.tokenPrefix)
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return []byte(p.signingSecret), nil
	})
	if err != nil || !token.Valid {
		rw.WriteHeader(http.StatusUnauthorized)
		msg := "invalid token"
		if err != nil {
			msg += ": " + err.Error()
		}
		if _, err := rw.Write([]byte(msg)); err != nil {
			fmt.Printf("failed to write response: %v\n", err)
		}
		return
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		rw.WriteHeader(http.StatusUnauthorized)
		if _, err := rw.Write([]byte("invalid claims")); err != nil {
			fmt.Printf("failed to write response: %v\n", err)
		}
		return
	}
	// Debug: dump claims
	if v := claims["exp"]; true {
		fmt.Printf("claims exp: %v, type: %T\n", v, v)
	}
	if v := claims["iat"]; true {
		fmt.Printf("claims iat: %v, type: %T\n", v, v)
	}
	p.forwardClaimsAndServe(rw, r, claims)
}

// checkAndWriteInvalidPrefix checks the token prefix and writes an error if invalid. Returns false if invalid.
func (p *JWTValidator) checkAndWriteInvalidPrefix(rw http.ResponseWriter, r *http.Request) bool {
	tokenString := r.Header.Get(p.authHeader)
	if !strings.HasPrefix(tokenString, p.tokenPrefix) {
		rw.WriteHeader(http.StatusUnauthorized)
		if _, err := rw.Write([]byte("invalid token prefix")); err != nil {
			fmt.Printf("failed to write response: %v\n", err)
		}
		return false
	}
	return true
}

// forwardClaimsAndServe forwards claims to headers and query params, then calls the next handler.
func (p *JWTValidator) forwardClaimsAndServe(rw http.ResponseWriter, r *http.Request, claims jwt.MapClaims) {
	r2 := r.Clone(r.Context())
	r2.Header = r.Header.Clone()
	urlCopy := *r.URL
	q := urlCopy.Query()
	for header, claimKey := range p.forwardHeaders {
		if v, ok := claims[claimKey]; ok {
			switch arr := v.(type) {
			case []interface{}:
				for _, item := range arr {
					r2.Header.Add(header, toString(item))
				}
			default:
				r2.Header.Set(header, toString(v))
			}
		}
	}
	for param, claimKey := range p.forwardQueryParams {
		if v, ok := claims[claimKey]; ok {
			queryKey := normalizeKey(param)
			switch arr := v.(type) {
			case []interface{}:
				for _, item := range arr {
					q.Add(queryKey, toString(item))
				}
			default:
				q.Add(queryKey, toString(v))
			}
		}
	}
	urlCopy.RawQuery = q.Encode()
	r2.URL = &urlCopy
	r2.RequestURI = r2.URL.RequestURI()
	p.next.ServeHTTP(rw, r2)
}

func normalizeKey(s string) string {
	res := strings.ReplaceAll(s, "-", "_")
	return strings.ToLower(res)
}

func toString(v interface{}) string {
	switch t := v.(type) {
	case string:
		return t
	case float64:
		return strings.TrimRight(strings.TrimRight(fmt.Sprintf("%f", t), "0"), ".")
	case bool:
		if t {
			return "true"
		}
		return "false"
	default:
		return ""
	}
}
