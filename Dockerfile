FROM node:10 AS build-env

WORKDIR /app

COPY package*.json server.js ./

RUN npm install

FROM gcr.io/distroless/nodejs:10

COPY --from=build-env /app /app

WORKDIR /app

EXPOSE 8080
CMD [ "server.js" ]
