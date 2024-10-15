package middleware

import (
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/deadmau5v/example-go-jwt/initializers"
	"github.com/deadmau5v/example-go-jwt/module"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

func RequrieAuth(ctx *gin.Context) {
	// 获取请求头的Cookie  Authorization
	jwt_token, err := ctx.Cookie("Authorization")
	if err != nil {
		log.Fatal(err)
		ctx.JSON(401, gin.H{"error": "内部错误 ra17"})
		ctx.Abort()
		return
	}

	// 如果没有直接返回401
	if strings.TrimSpace(jwt_token) == "" {
		ctx.JSON(401, gin.H{"error": "请登录"})
		ctx.Abort()
		return
	}

	// 解析验证token
	token, err := jwt.ParseWithClaims(jwt_token, jwt.MapClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(os.Getenv("JWT_SECRET")), nil
	}, jwt.WithLeeway(5*time.Second))
	if err != nil {
		log.Fatal(err)
		ctx.JSON(401, gin.H{"error": "内部错误 ra31"})
		ctx.Abort()
		return
	} else if claims, ok := token.Claims.(jwt.MapClaims); ok {
		userId := claims["sub"].(float64)
		timeStep := claims["exp"].(float64)

		if timeStep < float64(time.Now().Unix()) {
			ctx.JSON(401, gin.H{"error": "登录过期"})
			ctx.Abort()
			return
		}

		var user module.User
		initializers.DB.First(&user, userId)

		if user.ID == 0 {
			ctx.JSON(401, gin.H{"error": "无效的登录"})
			ctx.Copy().AbortWithStatus(http.StatusUnauthorized)
		}

		ctx.Set("user", user)

	} else {
		ctx.JSON(401, gin.H{"error": "无效的登录"})
		ctx.Abort()
		return
	}

	// 放行
	ctx.Next()

}
