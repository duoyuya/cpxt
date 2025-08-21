# 不使用-alpine后缀
FROM node:14

# 安装时区数据并配置时区
RUN apt-get update && apt-get install -y tzdata \
    && ln -sf /usr/share/zoneinfo/Asia/Shanghai /etc/localtime \
    && echo "Asia/Shanghai" > /etc/timezone

# 设置环境变量（双重保险）
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
