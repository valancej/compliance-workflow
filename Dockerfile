FROM mhart/alpine-node:12 

WORKDIR /usr/src/app

COPY package*.json ./

RUN npm install

FROM mhart/alpine-node:slim-12

WORKDIR /usr/src/app

COPY . .

EXPOSE 8080
CMD [ "node", "server.js" ]
