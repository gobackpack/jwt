package jwt_test

import (
	"github.com/gobackpack/jwt"
	"github.com/stretchr/testify/assert"
	"testing"
	"time"
)

func TestToken_Generate(t *testing.T) {
	token := &jwt.Token{
		Secret: []byte("testkey"),
	}

	tNow, err := time.Parse("02-01-2006 15:04:05", "01-01-2022 01:00:00")
	assert.NoError(t, err)

	tokenValue, err := token.Generate(map[string]interface{}{
		"id":  "id-123",
		"exp": tNow.UTC().Add(time.Minute * 5).Unix(),
	})

	expected := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE2NDA5OTkxMDAsImlkIjoiaWQtMTIzIn0._WI2plL_VWoq-ukd9QH_oZKYIAAnFbfeRzt8547zDZc"

	assert.NoError(t, err)
	assert.Equal(t, expected, tokenValue)
}

func TestToken_Generate_MissingSecret(t *testing.T) {
	token := &jwt.Token{
		Secret: []byte(""),
	}

	tokenValue, err := token.Generate(map[string]interface{}{
		"id":  "id-123",
		"exp": jwt.TokenExpiry(time.Minute * 5),
	})
	assert.Error(t, err)
	assert.Equal(t, "missing secret key", err.Error())
	assert.Empty(t, tokenValue)
}

func TestToken_ValidateAndExtract(t *testing.T) {
	token := &jwt.Token{
		Secret: []byte("testkey"),
	}

	tokenValue, err := token.Generate(map[string]interface{}{
		"id":  "id-123",
		"exp": jwt.TokenExpiry(time.Minute * 5),
	})
	assert.NoError(t, err)

	claims, valid := token.Validate(tokenValue)
	assert.NotEmpty(t, claims)
	assert.True(t, valid)

	id, ok := claims["id"]
	assert.True(t, ok)
	assert.Equal(t, "id-123", id)
}

func TestToken_ValidateAndExtract_ExpiredToken(t *testing.T) {
	token := &jwt.Token{
		Secret: []byte("testkey"),
	}

	tokenValue, err := token.Generate(map[string]interface{}{
		"id":  "id-123",
		"exp": jwt.TokenExpiry(time.Minute * (-5)),
	})
	assert.NoError(t, err)

	claims, valid := token.Validate(tokenValue)
	assert.Empty(t, claims)
	assert.False(t, valid)
}

func TestToken_ValidateAndExtract_InvalidSecret(t *testing.T) {
	token := &jwt.Token{
		Secret: []byte("testkey"),
	}

	tokenValue, err := token.Generate(map[string]interface{}{
		"id":  "id-123",
		"exp": jwt.TokenExpiry(time.Minute * 5),
	})
	assert.NoError(t, err)

	token.Secret = []byte("changed-secret")

	claims, valid := token.Validate(tokenValue)
	assert.Empty(t, claims)
	assert.False(t, valid)
}
