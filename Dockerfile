FROM node:14-alpine

WORKDIR /app

COPY "/package.json" "/package-lock.json" ./
RUN npm install --production && apk add --no-cache ca-certificates

COPY "/" .

EXPOSE 3000

CMD ["npm", "start"]
