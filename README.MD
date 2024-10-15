# Example Go JWT

使用 Go 实现 JWT 权限验证的最佳实践。

项目实现了简单的用户注册、登录、验证。

中间件/框架使用 Gorm、Gin、Postgresql...

# 项目结构

- **controller** 实现用户注册和登录
- **initializers** 实现数据库连接和迁移、读取环境变量
- **middleware** 实现 gin + jwt 鉴权中间件
- **module** 实现 user 模型

