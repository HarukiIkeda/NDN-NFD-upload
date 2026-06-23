FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1  

# NFDとPythonのインストール
RUN apt-get update && \
    apt-get install -y software-properties-common && \
    add-apt-repository ppa:named-data/ppa && \
    apt-get update && \
    apt-get install -y nfd ndn-tools python3 python3-pip && \
    rm -rf /var/lib/apt/lists/*

# python-ndn と暗号化ライブラリのインストール
RUN pip3 install python-ndn cryptography

# NFDの設定ファイル作成とデフォルトセキュリティキーの生成
RUN cp /etc/ndn/nfd.conf.sample /etc/ndn/nfd.conf && \
    ndnsec key-gen /localhost/operator | ndnsec cert-install -

WORKDIR /app
COPY . /app