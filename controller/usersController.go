package controller

import (
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/deadmau5v/example-go-jwt/initializers"
	"github.com/deadmau5v/example-go-jwt/module"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

func SingUp(ctx *gin.Context) {
	// 获取请求参数 email 和 password
	var requestBody struct {
		Email    string `json:"email" binding:"required,email"`
		Password string `json:"password" binding:"required,min=6"`
	}

	err := ctx.BindJSON(&requestBody)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "参数错误"})
	}

	// 验证参数
	if strings.TrimSpace(requestBody.Email) == "" || strings.TrimSpace(requestBody.Password) == "" {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "参数错误"})
		return
	}

	// 查询用户是否存在
	var user module.User
	result := initializers.DB.Where("email = ?", requestBody.Email).First(&user)
	if result.RowsAffected > 0 {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "用户已存在"})
		return
	}

	// 加密密码
	hash, err := bcrypt.GenerateFromPassword([]byte(requestBody.Password), bcrypt.DefaultCost)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "内部错误 uc45"})
		return
	}

	// 创建用户
	user = module.User{
		Email:    requestBody.Email,
		Password: string(hash),
	}

	result = initializers.DB.Create(&user)
	if result.Error != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "内部错误 uc57"})
		return
	}

	// 返回
	ctx.JSON(http.StatusOK, gin.H{"message": "注册成功"})
}

func Login(ctx *gin.Context) {
	// 获取请求参数 email 和 password
	var requestBody struct {
		Email    string `json:"email" binding:"required,email"`
		Password string `json:"password" binding:"required,min=6"`
	}

	ctx.BindJSON(&requestBody)

	// 判断参数是否合法
	if strings.TrimSpace(requestBody.Email) == "" || strings.TrimSpace(requestBody.Password) == "" {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "参数错误"})
		return
	}

	// 判断加密后的密码是否相等
	var user module.User
	initializers.DB.First(&user, "email = ?", requestBody.Email)

	if user.ID == 0 {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "用户不存在"})
		return
	}

	err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(requestBody.Password))
	if err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": "密码错误"})
		return
	}

	// 生成 token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": user.ID,
		"exp": time.Now().Add(time.Hour * 24 * 30).Unix(),
	})

	tokenString, err := token.SignedString([]byte(os.Getenv("JWT_SECRET")))
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, gin.H{"error": "内部错误 uc103"})
		return
	}

	ctx.SetSameSite(http.SameSiteStrictMode)
	ctx.SetCookie("Authorization", tokenString, 3600*24*30, "/", "", false, true)

	// 返回
	ctx.JSON(http.StatusOK, gin.H{"status": "success"})
	return
}

func ValiDate(ctx *gin.Context) {
	_user, _ := ctx.Get("user")
	user := _user.(module.User)

	ctx.JSON(http.StatusOK, gin.H{"status": "hello " + user.Email})
}
