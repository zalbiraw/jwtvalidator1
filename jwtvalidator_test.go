package github.com/zalbiraw/jwtvalidator

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"jwtvalidator"

	"github.com/golang-jwt/jwt/v4"
)

func generateJWT(secret string, claims map[string]interface{}) string {
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims(claims))
	tok, _ := t.SignedString([]byte(secret))
	return tok
}

func TestJWTValidator(t *testing.T) {
	cfg := jwtvalidator.CreateConfig()
	cfg.SigningSecret = "mysecret"
	cfg.ForwardHeaders = map[string]string{
		"Group":      "group",
		"Expires-At": "expires_at",
	}
	cfg.ForwardQueryParams = map[string]string{
		"group":      "group",
		"expires_at": "expires_at",
	}

	ctx := context.Background()
	var mutatedReq *http.Request
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		mutatedReq = req
	})

	handler, err := jwtvalidator.New(ctx, next, cfg, "jwt-validator-plugin")
	if err != nil {
		t.Fatal(err)
	}

	expVal := time.Now().Add(time.Hour).Unix()
	claims := map[string]interface{}{
		"group":      []interface{}{"engineering", "qa"},
		"expires_at": expVal,
	}
	token := generateJWT(cfg.SigningSecret, claims)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost/get?test=test", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)

	if mutatedReq == nil {
		t.Fatalf("next handler was not called; recorder code: %d, body: %s", recorder.Code, recorder.Body.String())
	}

	// Assert headers
	hVals := mutatedReq.Header["Group"]
	if len(hVals) != 2 || hVals[0] != "engineering" || hVals[1] != "qa" {
		t.Errorf("expected Group header to be [engineering qa], got %v", hVals)
	}
	if mutatedReq.Header.Get("Expires-At") != fmt.Sprintf("%d", expVal) {
		t.Errorf("expected Expires-At header to be %d, got %s", expVal, mutatedReq.Header.Get("Expires-At"))
	}

	// Assert query parameters
	q := mutatedReq.URL.Query()["group"]
	if len(q) != 2 || q[0] != "engineering" || q[1] != "qa" {
		t.Errorf("expected group query param to be [engineering qa], got %v", q)
	}
	if mutatedReq.URL.Query().Get("expires_at") != fmt.Sprintf("%d", expVal) {
		t.Errorf("expected expires_at query param to be %d, got %s", expVal, mutatedReq.URL.Query().Get("expires_at"))
	}
}

func TestJWTValidator_IATPresentAndMissing(t *testing.T) {
	cfg := jwtvalidator.CreateConfig()
	cfg.SigningSecret = "mysecret"
	cfg.ForwardHeaders = map[string]string{
		"Issued-At": "iat",
	}
	cfg.ForwardQueryParams = map[string]string{
		"issued_at": "iat",
	}

	ctx := context.Background()
	var mutatedReq *http.Request
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		mutatedReq = req
	})

	handler, err := jwtvalidator.New(ctx, next, cfg, "jwt-validator-plugin")
	if err != nil {
		t.Fatal(err)
	}

	// JWT with iat claim
	iatVal := time.Now().Unix()
	expVal := time.Now().Add(time.Hour).Unix()
	claimsWithIAT := map[string]interface{}{
		"iat": iatVal,
		"exp": expVal,
	}
	tokenWithIAT := generateJWT(cfg.SigningSecret, claimsWithIAT)

	reqWithIAT, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost/get", nil)
	if err != nil {
		t.Fatal(err)
	}
	reqWithIAT.Header.Set("Authorization", "Bearer "+tokenWithIAT)

	mutatedReq = nil
	handler.ServeHTTP(httptest.NewRecorder(), reqWithIAT)

	if mutatedReq == nil {
		t.Fatal("next handler was not called for iat-present")
	}
	// Assert iat header and query param present
	if mutatedReq.Header.Get("Issued-At") != fmt.Sprintf("%d", iatVal) {
		t.Errorf("expected Issued-At header to be %d, got %s", iatVal, mutatedReq.Header.Get("Issued-At"))
	}
	if mutatedReq.URL.Query().Get("issued_at") != fmt.Sprintf("%d", iatVal) {
		t.Errorf("expected issued_at query param to be %d, got %s", iatVal, mutatedReq.URL.Query().Get("issued_at"))
	}

	// JWT without iat claim
	claimsWithoutIAT := map[string]interface{}{
		"foo": "bar",
		"exp": time.Now().Add(time.Hour).Unix(),
	}
	tokenWithoutIAT := generateJWT(cfg.SigningSecret, claimsWithoutIAT)

	reqWithoutIAT, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost/get", nil)
	if err != nil {
		t.Fatal(err)
	}
	reqWithoutIAT.Header.Set("Authorization", "Bearer "+tokenWithoutIAT)

	mutatedReq = nil
	handler.ServeHTTP(httptest.NewRecorder(), reqWithoutIAT)

	if mutatedReq == nil {
		t.Fatal("next handler was not called for iat-missing")
	}
	// Assert iat header and query param missing
	if mutatedReq.Header.Get("Issued-At") != "" {
		t.Errorf("expected Issued-At header to be empty, got %s", mutatedReq.Header.Get("Issued-At"))
	}
	if mutatedReq.URL.Query().Get("issued_at") != "" {
		t.Errorf("expected issued_at query param to be empty, got %s", mutatedReq.URL.Query().Get("issued_at"))
	}
}

func TestJWTParseDirectly(t *testing.T) {
	secret := "mysecret"
	claims := map[string]interface{}{
		"group": []interface{}{"engineering", "qa"},
		"exp":   time.Now().Add(time.Hour).Unix(),
	}
	tokenString := generateJWT(secret, claims)

	parsed, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return []byte(secret), nil
	})
	if err != nil {
		t.Fatalf("jwt.Parse failed: %v", err)
	}
	if !parsed.Valid {
		t.Fatalf("jwt.Parse returned invalid token")
	}
}
