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
		"nbf": tNow.UTC().Add(time.Minute * 5).Unix(),
	})

	expected := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6ImlkLTEyMyIsIm5iZiI6MTY0MDk5OTEwMH0.hqd1XP7ZPwJ375Cv6gV1jLMjvNheZcWvUfPNt5qkfs8"

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

	claims, valid := token.ValidateAndExtract(tokenValue)
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

	claims, valid := token.ValidateAndExtract(tokenValue)
	assert.Empty(t, claims)
	assert.False(t, valid)
}
