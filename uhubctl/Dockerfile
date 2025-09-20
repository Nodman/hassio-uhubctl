ARG BUILD_FROM
FROM ${BUILD_FROM}

RUN \
    set -x \
    && apk add --no-cache --virtual .build-dependencies \
        build-base \
        linux-headers \
	libusb-dev \
	wget \
	python3 \
 	py3-paho-mqtt

RUN wget https://github.com/mvp/uhubctl/archive/refs/tags/v2.6.0.tar.gz -O /tmp/uhubctl-v2.6.0.tar.gz && \
    cd /tmp && tar -xzf uhubctl-v2.6.0.tar.gz && \
    cd uhubctl-2.6.0 && make && make install

COPY . /app
WORKDIR /app

RUN chmod a+x run.sh

CMD ["/app/run.sh"]
