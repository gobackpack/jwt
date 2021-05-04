package jwt

import (
	"errors"
	jwtLib "github.com/dgrijalva/jwt-go"
)

var ErrMissingSecret = errors.New("missing secret key")

type Token struct {
	Secret []byte
}

func (token *Token) Generate(claims map[string]interface{}) (string, error) {
	if token.Secret == nil || len(token.Secret) == 0 {
		return "", ErrMissingSecret
	}

	jwtClaims := jwtLib.MapClaims{}
	for k, v := range claims {
		jwtClaims[k] = v
	}

	jwtToken := jwtLib.NewWithClaims(jwtLib.SigningMethodHS256, jwtClaims)

	tokenStr, err := jwtToken.SignedString(token.Secret)
	if err != nil {
		return "", err
	}

	return tokenStr, nil
}

func (token *Token) ValidateAndExtract(tokenStr string) (map[string]interface{}, bool) {
	jwtToken, err := token.parse(tokenStr)
	if err != nil {
		return nil, false
	}

	if jwtClaims, valid := token.valid(jwtToken); valid {
		if claims, ok := jwtClaims.(jwtLib.MapClaims); ok {
			claimsMap := map[string]interface{}{}

			for k, v := range claims {
				claimsMap[k] = v
			}

			return claimsMap, true
		}
	}

	return nil, false
}

func (token *Token) parse(tokenStr string) (*jwtLib.Token, error) {
	jwtToken, err := jwtLib.Parse(tokenStr, func(t *jwtLib.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwtLib.SigningMethodHMAC); !ok {
			return nil, errors.New("failed to parse JWT token")
		}

		return token.Secret, nil
	})

	return jwtToken, err
}

func (token *Token) valid(jwtToken *jwtLib.Token) (jwtLib.Claims, bool) {
	if jwtToken != nil {
		claims, ok := jwtToken.Claims.(jwtLib.Claims)

		return claims, ok && jwtToken.Valid
	}

	return nil, false
}
