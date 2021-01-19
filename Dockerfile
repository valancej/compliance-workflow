FROM registry.access.redhat.com/ubi8/ubi-minimal 

RUN microdnf install nodejs && microdnf clean all

WORKDIR /usr/src/app

COPY package*.json ./

RUN npm install

COPY . .

EXPOSE 8080
CMD [ "node", "server.js" ]
