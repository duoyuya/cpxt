FROM node:14-alpine
RUN apk add --no-cache ca-certificates  # 安装CA证书
WORKDIR /app
COPY package*.json ./
RUN npm install --production
COPY . .
EXPOSE 3000
CMD ["npm", "start"]
