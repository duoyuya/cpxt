# 不使用-alpine后缀
FROM node:14

# 非交互式安装tzdata并配置时区
RUN DEBIAN_FRONTEND=noninteractive apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends tzdata && \
    ln -sf /usr/share/zoneinfo/Asia/Shanghai /etc/localtime && \
    echo "Asia/Shanghai" > /etc/timezone && \
    rm -rf /var/lib/apt/lists/*  # 清理缓存减小镜像体积

# 设置环境变量
ENV TZ=Asia/Shanghai

WORKDIR /app

# 切换npm镜像源
RUN npm config set registry https://registry.npmmirror.com/

# 复制依赖文件
COPY "package.json" "package-lock.json" ./

# 安装依赖
RUN npm install --production --verbose

# 复制项目文件
COPY . .

EXPOSE 3000

CMD ["npm", "start"]
