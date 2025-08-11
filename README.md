# 车辆通知系统

## 项目介绍
车辆通知系统是一个基于Node.js的后台服务，支持车牌管理和通知发送功能，提供Web后台管理界面，可通过Docker快速部署，并支持自定义车牌前缀配置。

## 项目功能
- 车牌信息管理（添加、编辑、查询、删除）
- 通知发送与记录追踪
- Web后台管理界面（支持主题切换）
- 数据持久化存储（SQLite数据库）
- 支持自定义车牌前缀（默认"云M"）
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

## 目录结构说明
```
.
├── .env                # 环境配置文件（需手动创建）
├── docker-compose.yml  # Docker Compose配置文件
├── data/               # 应用数据持久化目录（自动创建，包含SQLite数据库）
└── README.md           # 项目说明文档
```

## 车牌前缀修改指南
系统默认车牌前缀为"云M"，如需修改为其他省份简称（如"京A"、"沪B"等），需按以下步骤操作（**需先Fork项目并修改代码**）：

### 前置条件
- 文本编辑器（如VS Code）
- Git（用于提交修改）
- Docker（可选，用于本地测试）
- 对项目文件结构的基本了解

### 修改步骤

#### 1. 后端修改（共2处）
**文件路径**: `server.js`

##### 1.1 修改通知查询前缀
找到通知发送API中的车牌查询语句（约350行）：
```javascript
// 查询车牌信息
db.get("SELECT * FROM plates WHERE plate = ?", [`云M${plate}`], (err, plateInfo) => { ... })
```
**修改为**（以"京A"为例）：
```javascript
db.get("SELECT * FROM plates WHERE plate = ?", [`京A${plate}`], (err, plateInfo) => { ... })
```

##### 1.2 修改车牌格式验证正则
找到添加车牌接口中的正则表达式（约220行）：
```javascript
const plateRegex = /^[云京津冀晋蒙辽吉黑沪苏浙皖闽赣鲁豫鄂湘粤桂琼渝川黔滇藏陕甘青宁新][A-Z0-9]{5,7}$/;
```
**修改为**（以仅允许"京"开头为例）：
```javascript
const plateRegex = /^[京][A-Z0-9]{5,7}$/;
```
> 如需支持多省份，可改为 `/^[京沪粤][A-Z0-9]{5,7}$/`（同时支持京、沪、粤）

#### 2. 前端修改（共2处）
**文件路径**: `admin/plate-management.html`

##### 2.1 修改车牌输入框前缀显示
找到添加/编辑车牌模态框中的前缀显示（约850行）：
```html
<span style="padding: 10px 14px; background: var(--primary-light); color: var(--primary); border: 1px solid var(--border); border-right: none; border-radius: 8px 0 0 8px;">云M</span>
```
**修改为**（以"京A"为例）：
```html
<span style="padding: 10px 14px; background: var(--primary-light); color: var(--primary); border: 1px solid var(--border); border-right: none; border-radius: 8px 0 0 8px;">京A</span>
```

##### 2.2 修改编辑车牌时的前缀处理
找到编辑车牌时的前缀去除逻辑（约1650行）：
```javascript
document.getElementById('modalPlateNumber').value = plate.replace('云M', '');
```
**修改为**（以"京A"为例）：
```javascript
document.getElementById('modalPlateNumber').value = plate.replace('京A', '');
```

### 验证方法
1. **本地验证**（修改后）：
   ```bash
   cd cpxt-main
   npm install
   npm start
   ```
   访问后台测试添加/编辑车牌及通知发送功能。

2. **线上验证**：
   - 提交修改到GitHub仓库
   - 等待GitHub Actions自动构建新镜像
   - 更新`docker-compose.yml`中的镜像版本
   - 重新部署：`docker-compose pull && docker-compose up -d`

## 注意事项
1. **数据安全**：
   - 生产环境务必修改默认密码和JWT密钥
   - 定期备份`./data`目录下的数据库文件

2. **网络配置**：
   - DNS设置确保容器内可解析外部域名（如WxPusher API）
   - 如需代理，可在Docker Compose中添加`HTTP_PROXY`环境变量

3. **车牌前缀修改补充**：
   - 前后端四处修改的前缀必须完全一致
   - 前缀中的字母必须大写（如"京A"而非"京a"）
   - 修改前缀后，原有车牌数据需手动更新或批量迁移
   - 修改前建议备份相关文件，以便出现问题时恢复

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

### Q: 车牌前缀修改后验证失败？
A: 
- 若添加车牌提示"格式不正确"：检查`server.js`中的正则表达式是否正确
- 若前缀未更新：确认`plate-management.html`中的两处修改是否都已完成
- 若通知提示"车牌不存在"：检查`server.js`中的查询语句是否使用了新前缀

### Q: Docker构建失败？
A: 查看GitHub Actions构建日志，常见原因：
- 代码格式错误（如JSON语法错误）
- 依赖安装失败（可尝试切换npm镜像源）
- 文件路径错误（确保修改的文件路径正确）
