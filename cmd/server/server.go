package main

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httputil"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt"
)

var jwtKey = []byte("my_secret_key")

func main() {
	http.HandleFunc("/multiply", DumpRequest(AuthMiddleware([]string{}, MultiplyHandler)))
	http.HandleFunc("/token", DumpRequest(TokenHandler))

	log.Println("Server started on :8080")
	err := http.ListenAndServe(":8080", nil)
	if err != nil {
		log.Fatal(err)
	}
}

// ----------------------------------------------------------------------------

func DumpRequest(next http.HandlerFunc) http.HandlerFunc {
	writer := os.Stdout
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if data, err := httputil.DumpRequest(r, true); err == nil {
			writer.Write(data)
			writer.Write([]byte("\n"))
		}
		next.ServeHTTP(w, r)
	})
}

// ----------------------------------------------------------------------------

type MultiplyRequest struct {
	A int `json:"a"`
	B int `json:"b"`
}

type MultiplyResponse struct {
	Result int `json:"result"`
}

func MultiplyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req MultiplyRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		log.Println(err)
		return
	}

	result := req.A * req.B
	resp := MultiplyResponse{Result: result}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// ----------------------------------------------------------------------------

type Claims struct {
	ClientID string   `json:"client_id"`
	Scopes   []string `json:"scopes"`
	jwt.StandardClaims
}

func AuthMiddleware(requiredScopes []string, next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenString, ok := BearerAuth(r)
		if !ok {
			http.Error(w, "Authorization header is required", http.StatusUnauthorized)
			return
		}

		claims := &Claims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})

		if err != nil || !token.Valid {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		// Check if the token has the required scopes
		scopeMap := make(map[string]bool)
		for _, scope := range claims.Scopes {
			scopeMap[scope] = true
		}

		for _, requiredScope := range requiredScopes {
			if !scopeMap[requiredScope] {
				http.Error(w, "Insufficient scope", http.StatusForbidden)
				return
			}
		}

		ctx := context.WithValue(r.Context(), "client_id", claims.ClientID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func BearerAuth(r *http.Request) (string, bool) {
	auth := r.Header.Get("Authorization")
	prefix := "Bearer "
	token := ""

	if auth != "" && strings.HasPrefix(auth, prefix) {
		token = auth[len(prefix):]
	} else if r.PostForm.Has("access_token") {
		token = r.FormValue("access_token")
	} else {
		token = r.URL.Query().Get("access_token")
	}

	return token, token != ""
}

// ----------------------------------------------------------------------------

type TokenRequest struct {
	GrantType    string `json:"grant_type"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	Scope        string `json:"scope"`
}

type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

func TokenHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	tokenRequest, err := ParseTokenRequest(r)
	if err != nil {
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}
	// Validate the token request
	if tokenRequest.GrantType != "client_credentials" {
		http.Error(w, "Invalid grant type", http.StatusBadRequest)
		return
	}

	// Extract scope from the token request
	scopes := strings.Fields(r.URL.Query().Get("scope"))

	// Validate the credentials
	if tokenRequest.ClientID != "000000" || tokenRequest.ClientSecret != "999999" {
		http.Error(w, "Invalid client credentials", http.StatusUnauthorized)
		return
	}

	expirationTime := time.Now().Add(1 * time.Hour)
	claims := &Claims{
		ClientID: tokenRequest.ClientID,
		Scopes:   scopes, // Add the scope to the claims
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		http.Error(w, "Could not create token", http.StatusInternalServerError)
		return
	}

	resp := TokenResponse{
		AccessToken: tokenString,
		TokenType:   "Bearer",
		ExpiresIn:   int(time.Until(expirationTime).Seconds()),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func ParseTokenRequest(r *http.Request) (TokenRequest, error) {
	var req TokenRequest

	// Parse the query string
	query := r.URL.Query()

	// Extract values from query parameters
	req.GrantType = query.Get("grant_type")
	req.ClientID = query.Get("client_id")
	req.ClientSecret = query.Get("client_secret")
	req.Scope = query.Get("scope")

	// You can add validation or error checking here if needed

	return req, nil
}
