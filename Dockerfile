FROM node:14  # 不使用-alpine后缀
WORKDIR /app
COPY package*.json ./
RUN npm config set registry https://registry.npmmirror.com/ && npm install --production
COPY . .
EXPOSE 3000
CMD ["npm", "start"]
