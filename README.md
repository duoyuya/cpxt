# 车辆通知系统

## 项目介绍
车辆通知系统是一个基于Node.js的后台服务，支持车牌管理和通知发送功能，提供Web后台管理界面，可通过Docker快速部署，并支持自定义车牌前缀配置。

## 项目功能
- 车牌信息管理（添加、编辑、查询、删除）
- 通知发送与记录追踪
- Web后台管理界面
- 数据持久化存储（SQLite数据库）
- 操作日志记录与管理

## 环境要求
- Docker Engine
- Docker Compose (v3.8+)
- 网络连接（用于拉取镜像和发送通知）

## 快速开始

### 1. 准备环境配置文件
在项目根目录创建`.env`文件，内容如下：
```env
# 服务器配置
PORT=3000

# 管理员账户配置
ADMIN_USER=admin
ADMIN_PASSWORD_HASH=$2a$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi  # 默认密码: password

# JWT配置
JWT_SECRET=your_jwt_secret_key_here  # 建议修改为随机字符串
JWT_EXPIRES_IN=24h
```

### 2. 修改管理员密码（可选）
1. 访问 [bcrypt-generator.com](https://bcrypt-generator.com/)
2. 输入新密码（如`123456`）
3. 工作因子保持默认`10`
4. 点击"Generate Bcrypt Hash"生成哈希值
5. 替换`.env`文件中`ADMIN_PASSWORD_HASH`的值

### 3. 创建Docker Compose配置
在项目根目录创建`docker-compose.yml`文件：
```yaml
version: '3.8'
services:
  car-system:
    image: ghcr.io/duoyuya/cpxt:latest  # 替换为你的镜像地址
    container_name: car-system
    restart: always
    ports:
      - "3000:3000"
    volumes:
      - ./data:/app/data  # 数据持久化
      - ./.env:/app/.env   # 环境变量配置
    environment:
      - TZ=Asia/Shanghai   # 时区设置
    dns:
      # 补充DNS配置，避免域名解析失败导致网络不通
      - 8.8.8.8
      - 114.114.114.114
```

### 4. 启动服务
```bash
docker-compose up -d
```

## 访问地址
- **系统主页**: http://localhost:3000
- **后台登录**: http://localhost:3000/admin/login.html
  - 默认账号: admin
  - 默认密码: password（如未修改）

## 常见问题

### Q: 启动后无法访问服务？
A: 检查端口是否被占用，Docker服务是否正常运行，查看日志：
```bash
docker-compose logs -f
```

### Q: 通知发送失败？
A: 检查DNS配置是否生效，网络是否通畅，可进入容器测试网络：
```bash
docker exec -it car-system ping wxpusher.zjiecode.com
```
