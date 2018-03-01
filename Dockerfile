FROM php:7.2-fpm

# Keep composer happy
ENV COMPOSER_ALLOW_SUPERUSER 1
# Keep nullmailer from pestering for a name
ENV DEBIAN_FRONTEND noninteractive

EXPOSE 80

WORKDIR /

RUN apt-get update \
  && apt-get install -y gnupg \
  && curl -sL https://deb.nodesource.com/setup_9.x | bash - \
  && echo 'deb http://apt.newrelic.com/debian/ newrelic non-free' > /etc/apt/sources.list.d/newrelic.list \
  && curl -fsSL https://download.newrelic.com/548C16BF.gpg | apt-key add - \
  && apt-get update \
  && apt-get -o Dpkg::Options::="--force-confdef" -o Dpkg::Options::="--force-confold" -y install \
  fuse \
  git \
  gnupg \
  libffi-dev \
  mariadb-client \
  newrelic-php5 \
  nginx \
  nginx-extras \
  nullmailer \
  nodejs \
  python-pip \
  ruby-dev \
  sass \
  supervisor \
  && apt-get clean

RUN php -r "copy('https://getcomposer.org/installer', 'composer-setup.php');" \
  && php -r "if (hash_file('SHA384', 'composer-setup.php') === '544e09ee996cdf60ece3804abc52599c22b1f40f4323403c44d44fdfdd586475ca9813a858088ffbc1f233e9b180f061') { echo 'Installer verified'; } else { echo 'Installer corrupt'; unlink('composer-setup.php'); } echo PHP_EOL;" \
  && php composer-setup.php --install-dir=/usr/local/bin --filename=composer \
  && php -r "unlink('composer-setup.php');"

RUN pip install yas3fs

WORKDIR /bedrock
COPY composer.json .
COPY bedrock.json .
COPY moj.json .

COPY Gruntfile.js .
COPY package.json .

COPY mojintranet web/app/themes/mojintranet/

RUN mkdir -p web/app/uploads \
  && composer install --verbose \
  && rm bedrock.json \
  && rm composer.json \
  && rm moj.json \
  && rm composer.lock

RUN npm install --global grunt-cli \
  && npm install \
  && grunt pre_deploy \
  && rm Gruntfile.js

RUN cd /bedrock/web/app/themes/intranet-theme-clarity \
  && npm install --global gulp-cli \
  && npm install \
  && gulp build \
  && cd /bedrock \
  && rm -rf node_modules \
  && rm package.json \
  && rm package-lock.json

WORKDIR /

COPY etc/nginx/nginx.conf /etc/nginx/
COPY etc/nginx/php-fpm.conf /etc/nginx/
COPY etc/nginx/sites-available/default /etc/nginx/sites-available/
COPY etc/nginx/whitelists/pingdom.conf /etc/nginx/whitelists/
COPY etc/supervisor/supervisord.conf /etc/supervisor/
COPY etc/php /etc/php

COPY runonce runonce/

COPY config/application.php /bedrock/config/
COPY config/environments/ /bedrock/config/

CMD ["/usr/bin/supervisord"]
