from nginx:latest

## TODO: LetsEncrypt
# RUN echo "deb http://ftp.debian.org/debian jessie-backports main" >> /etc/apt/sources.list
# RUN apt-get update
# RUN apt-get install -y certbot -t jessie-backports

ADD nginx.conf /etc/nginx/nginx.conf
ADD provewhen.io.conf /etc/nginx/conf.d/provewhen.io.conf

ADD provewhen-io /var/www/provewhen-io

# TODO
# ADD dh.pem /etc/nginx/dh-param.pem
