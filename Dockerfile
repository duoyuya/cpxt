FROM node:18-alpine

WORKDIR /app

# 安装系统依赖
RUN apk add --no-cache bash git python3 make g++

# 切换npm镜像源
RUN npm config set registry https://registry.npmmirror.com/

# 复制依赖文件
COPY package*.json ./

# 安装依赖
RUN npm install --production

# 创建数据目录并设置权限
RUN mkdir -p /app/data && chmod -R 777 /app/data

# 复制项目文件
COPY . .

# 复制环境变量文件
COPY .env.example .env

EXPOSE 3000

# 添加启动脚本，处理数据库初始化
CMD ["sh", "-c", "npm run migrate && npm start"]
