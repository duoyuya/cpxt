FROM node:14-alpine AS builder

WORKDIR /app

# 切换npm镜像源并安装tzdata
RUN npm config set registry https://registry.npmmirror.com/ && \
    apk add --no-cache tzdata

# 设置时区为中国上海
ENV TZ=Asia/Shanghai

# 复制依赖文件
COPY package*.json ./

# 安装依赖
RUN npm install --production --verbose && \
    npm prune --production && \
    rm -rf node_modules/.cache

# 复制项目文件
COPY . .

# 第二阶段：运行环境
FROM node:14-alpine

WORKDIR /app

# 安装tzdata并设置时区
RUN apk add --no-cache tzdata && \
    ln -sf /usr/share/zoneinfo/Asia/Shanghai /etc/localtime && \
    echo "Asia/Shanghai" > /etc/timezone

ENV TZ=Asia/Shanghai

# 复制构建产物
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/package*.json ./
COPY --from=builder /app/server.js ./
COPY --from=builder /app/admin ./admin
COPY --from=builder /app/data ./data

EXPOSE 3000

CMD ["npm", "start"]
