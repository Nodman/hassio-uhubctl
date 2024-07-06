ARG BUILD_FROM
FROM ${BUILD_FROM}

RUN \
    set -x \
    && apk add --no-cache --virtual .build-dependencies \
        build-base \
        linux-headers \
	libusb-dev \
	git \
	python3 \
 	py3-paho-mqtt

RUN git clone https://github.com/mvp/uhubctl.git /tmp/uhubctl && \
    cd /tmp/uhubctl && make && make install

COPY . /app
WORKDIR /app

RUN chmod a+x run.sh

CMD ["/app/run.sh"]
