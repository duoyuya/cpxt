# 使用包含时区数据的基础镜像
FROM node:14-buster

# 直接设置时区（无需安装任何包）
ENV TZ=Asia/Shanghai
RUN ln -sf /usr/share/zoneinfo/${TZ} /etc/localtime && \
    echo ${TZ} > /etc/timezone

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
