FROM node:14-alpine

WORKDIR /app

# 复制依赖文件
COPY "package.json" "package-lock.json" ./

# 单独执行npm install并输出详细日志（关键修改）
RUN npm install --production --verbose

# 单独安装CA证书
RUN apk add --no-cache ca-certificates

# 复制项目文件
COPY . .

EXPOSE 3000

CMD ["npm", "start"]
