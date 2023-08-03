FROM ubuntu:20.04
LABEL vendor="Virtru Corporation"

# build-essential for cmake/make


RUN apt-get update \
  && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
  build-essential \
  valgrind \
  cmake \
  lcov \
  html2text \
  git \
  openssh-client \
  wget \
  python3-pip \
  python3-setuptools \
  python3-dev \
  python3-venv \
  netbase \
  doxygen \
  gnuplot \
  openjdk-8-jdk \
  maven \
  swig \
  curl \
  jq \
  gcc-9 && \
  update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-9 60 --slave /usr/bin/g++ g++ /usr/bin/g++-9 && \
  update-alternatives --config gcc \
  && rm -rf /var/lib/apt/lists/*

# valgrind=1:3.15.0-1ubuntu9.1
# Install AWS CLI
RUN pip3 --no-cache-dir install awscli==1.19.72

# Publish java install location
ENV JAVA_HOME /usr/lib/jvm/java-8-openjdk-amd64/
RUN export JAVA_HOME

# install conan
RUN pip3 install --no-cache-dir conan==1.57.0
RUN pip3 install --no-cache-dir virtualenv==20.4.6

# install golang
RUN wget --progress=dot:giga -c https://storage.googleapis.com/golang/go1.13.linux-amd64.tar.gz
RUN tar -C /usr/local -xzf go1.13.linux-amd64.tar.gz
RUN export PATH=$PATH:/usr/local/go/bin

WORKDIR /app
