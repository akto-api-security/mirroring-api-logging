FROM node:23.10.0-alpine3.21
WORKDIR /usr/src/app
COPY . .
EXPOSE 8000
CMD [ "node", "hello.js" ]