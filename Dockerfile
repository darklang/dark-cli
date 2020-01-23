FROM circleci/rust:1.40.0-stretch

ENV DEBIAN_FRONTEND noninteractive

USER root
RUN apt update \
  && apt upgrade -y \
  && apt install -y --no-install-recommends \
    curl \
    apt-transport-https \
    ca-certificates \
    lsb-core \
    git \
    sudo \
    pkg-config \
    build-essential \
    gcc \
    clang \
    gcc-mingw-w64-x86-64 \
    llvm-4.0-dev \
    musl-tools \
  && apt clean \
  && rm -rf /var/lib/apt/lists/*

############################
# Dark user
############################
USER root
RUN adduser --disabled-password --gecos '' dark
RUN echo "dark:dark" | chpasswd && adduser dark sudo
RUN chown -R dark:dark /home/dark
RUN echo '%sudo ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers
USER dark
WORKDIR /home/dark

############################
# Shellcheck
# Ubuntu has a very old version
############################

RUN \
  VERSION=v0.6.0 \
  && FILENAME=shellcheck-$VERSION.linux.x86_64.tar.xz  \
  && wget -P tmp_install_folder/ https://shellcheck.storage.googleapis.com/$FILENAME \
  && tar xvf tmp_install_folder/$FILENAME -C tmp_install_folder \
  && sudo cp tmp_install_folder/shellcheck-$VERSION/shellcheck /usr/bin/shellcheck \
  && rm -Rf tmp_install_folder

# install Rust dev tools
RUN rustup component add clippy-preview rustfmt-preview

ENV TERM=xterm-256color

RUN rustup target add x86_64-apple-darwin \
  && rustup target add x86_64-pc-windows-gnu \
  && rustup target add x86_64-unknown-linux-musl

RUN curl -O https://dark-osxcross-files.storage.googleapis.com/osxcross-with-clang.tar.gz \
  && tar -xf osxcross-with-clang.tar.gz \
  && rm osxcross-with-clang.tar.gz
ENV PATH "$PATH:/home/dark/target/bin"

USER dark
WORKDIR /home/dark/dark-cli

CMD /bin/bash
