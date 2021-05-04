package main

import (
	jwtLib "github.com/gobackpack/jwt"
	"log"
	"time"
)

func main() {
	token := &jwtLib.Token{
		Secret: []byte("testkey"),
	}

	tokenStr, err := token.Generate(map[string]interface{}{
		"id":    "semir-123",
		"email": "semir@mail.com",
		"exp":   jwtLib.TokenExpiry(time.Second * 15),
	})
	if err != nil {
		log.Fatalln("failed to generate jwt: ", err)
	}

	log.Print(tokenStr)

	claims, valid := token.ValidateAndExtract(tokenStr)
	if !valid {
		log.Print("invalid token: ", tokenStr)
	}

	log.Print("claims: ", claims)
}
