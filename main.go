package main

import (
	"github.com/deadmau5v/example-go-jwt/controller"
	"github.com/deadmau5v/example-go-jwt/initializers"
	"github.com/deadmau5v/example-go-jwt/middleware"
	"github.com/gin-gonic/gin"
)

func init() {
	initializers.LoadEnv()
	initializers.ConnectToPostgres()
	initializers.SyncDb()
}

func main() {
	app := gin.Default()
	api := app.Group("/api")
	api.Use(middleware.RequrieAuth)
	api.GET("/validate", controller.ValiDate)

	noAuth := app.Group("/api")
	noAuth.POST("/signup", controller.SingUp)
	noAuth.POST("/login", controller.Login)

	app.Run()
}
