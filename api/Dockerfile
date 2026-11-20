# Keep the supported LTS major; refresh the latest security-patched 24.x base at each verified build.
FROM node:24-alpine
RUN apk add --no-cache docker-cli openssl tzdata
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
EXPOSE 3000
CMD ["npm", "start"]