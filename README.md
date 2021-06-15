![alt Go](https://img.shields.io/github/go-mod/go-version/gobackpack/jwt)

### JWT

* **Generate jwt with claims**
```
token := &jwtLib.Token{
    Secret: []byte("testkey"),
}

tokenStr, err := token.Generate(map[string]interface{}{
    "id":    "semir-123",
    "email": "semir@mail.com",
    "exp":   time.Now().Add(time.Second * 15).Unix(),
})
if err != nil {
    log.Fatalln("failed to generate jwt: ", err)
}

log.Print(tokenStr)
```

* **Validate and get jwt claims**
```
claims, valid := token.ValidateAndExtract(tokenStr)
if !valid {
    log.Print("invalid token: ", tokenStr)
}

log.Print("claims: ", claims)
```
