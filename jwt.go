package jwt

import (
	"errors"
	jwtLib "github.com/golang-jwt/jwt/v4"
	"time"
)

type Token struct {
	Secret []byte
}

func (t *Token) Generate(claims map[string]interface{}) (string, error) {
	if t.Secret == nil || len(t.Secret) == 0 {
		return "", errors.New("missing secret key")
	}

	jwtClaims := jwtLib.MapClaims{}
	for k, v := range claims {
		jwtClaims[k] = v
	}

	jwtToken := jwtLib.NewWithClaims(jwtLib.SigningMethodHS256, jwtClaims)

	return jwtToken.SignedString(t.Secret)
}

func (t *Token) ValidateAndExtract(token string) (map[string]interface{}, bool) {
	jwtToken, err := parseToken(t.Secret, token)
	if err != nil {
		return nil, false
	}

	if jwtClaims, valid := validToken(jwtToken); valid {
		claims := map[string]interface{}{}
		for k, v := range jwtClaims {
			claims[k] = v
		}

		return claims, true
	}

	return nil, false
}

func TokenExpiry(duration time.Duration) int64 {
	return time.Now().UTC().Add(duration).Unix()
}

func parseToken(secret []byte, tokenStr string) (*jwtLib.Token, error) {
	jwtToken, err := jwtLib.Parse(tokenStr, func(libToken *jwtLib.Token) (interface{}, error) {
		if _, ok := libToken.Method.(*jwtLib.SigningMethodHMAC); !ok {
			return nil, errors.New("failed to parse JWT")
		}

		return secret, nil
	})

	return jwtToken, err
}

func validToken(jwtToken *jwtLib.Token) (jwtLib.MapClaims, bool) {
	jwtClaims, ok := jwtToken.Claims.(jwtLib.MapClaims)

	return jwtClaims, ok && jwtToken.Valid
}
