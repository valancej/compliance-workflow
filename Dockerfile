FROM registry.access.redhat.com/ubi8:8.3 

RUN yum -y install nodejs

WORKDIR /usr/src/app

COPY package*.json ./

RUN npm install

COPY . .

EXPOSE 8080
CMD [ "node", "server.js" ]
