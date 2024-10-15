package initializers

import "github.com/deadmau5v/example-go-jwt/module"

func SyncDb() {
	DB.AutoMigrate(&module.User{})
}
