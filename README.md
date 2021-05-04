### JWT

* **Generate jwt with claims**
```
token := &jwtLib.Token{
    Secret: []byte("testkey"),
}

tokenStr, err := token.Generate(map[string]interface{}{
    "id":    "semir-123",
    "email": "semir@mail.com",
    "exp":   time.Second * 15,
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