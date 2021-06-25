ARG LIBOQS_BUILD_DEFINES="-DOQS_USE_CPU_EXTENSIONS=OFF"
ARG OPENSSL_PATH=/opt/openssl
ARG MAKE_DEFINES="-j 4"

FROM alpine as intermediate

ARG LIBOQS_BUILD_DEFINES
ARG OPENSSL_PATH
ARG MAKE_DEFINES

RUN sed -i 's/dl-cdn.alpinelinux.org/mirrors.aliyun.com/' /etc/apk/repositories

# Get all software packages required for builing all components:
RUN apk add --no-cache build-base linux-headers \
            libtool automake autoconf cmake ninja \
            make \
            openssl openssl-dev \
            git wget pcre-dev \
            gcc musl-dev python3 py3-pip

# get OQS sources
WORKDIR /opt
RUN git clone --depth 1 --branch main https://github.com/open-quantum-safe/liboqs && \
    git clone --depth 1 --branch OQS-OpenSSL_1_1_1-stable https://github.com/open-quantum-safe/openssl

# build liboqs (static only)
WORKDIR /opt/liboqs
RUN mkdir build-static && cd build-static && cmake -G"Ninja" ${LIBOQS_BUILD_DEFINES} -DBUILD_SHARED_LIBS=OFF -DCMAKE_INSTALL_PREFIX=${OPENSSL_PATH}/oqs .. && ninja && ninja install

# build nginx (which builds OQS-OpenSSL)
WORKDIR /opt/openssl
RUN ./Configure no-shared linux-x86_64 -lm && make -j

WORKDIR /
COPY . .
RUN pip install gunicorn wheel
RUN pip install -r requirements.txt
ENV FLASK_APP=cert.py
ENV FLASK_RUN_HOST=0.0.0.0

RUN apk add pcre-dev

EXPOSE 5000

STOPSIGNAL SIGTERM

CMD ["gunicorn", "--bind", "0.0.0.0:5000", "cert:app"]