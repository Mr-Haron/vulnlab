FROM node:20-alpine
WORKDIR /usr/src/admin
COPY package*.json ./
RUN npm install
COPY . .
EXPOSE 4000
CMD ["node", "server.js"]
