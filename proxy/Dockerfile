FROM nginx:stable-alpine

RUN apk add --no-cache certbot

COPY nginx/basic.conf /opt/proxy/basic.conf
COPY nginx/oauth2.conf /opt/proxy/oauth2.conf
COPY start-with-certbot.sh /usr/local/bin/start-with-certbot
RUN chmod 0755 /usr/local/bin/start-with-certbot

ENTRYPOINT ["/usr/local/bin/start-with-certbot"]
