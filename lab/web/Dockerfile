# Web victim for the lab: stock nginx with a log written to a real file
# (the stock image symlinks access.log to stdout, which can't be shipped).
FROM nginx:1.27-alpine

RUN mkdir -p /var/log/lab
COPY nginx.conf /etc/nginx/nginx.conf
