# Note: We don't use Alpine and its packaged Rust/Cargo because they're too often out of date,
# preventing them from being used to build Substrate/Polkadot.

FROM phusion/baseimage:0.10.2 as builder
LABEL description="This is the build stage. Here we create the binary."

ARG PROFILE=release

RUN curl https://sh.rustup.rs -sSf | sh -s -- -y && \
    export PATH=$PATH:$HOME/.cargo/bin && \
    rustup toolchain install nightly && \
	rustup default nightly && \
 	rustup default stable && \
    cargo new --bin baf-progressive-wallet

# pseudo cache for dependencies
WORKDIR ./baf-progressive-wallet
COPY ./Cargo.toml ./Cargo.toml

# llvm and liblcang
RUN apt-get update && \
# 	# apt-get upgrade -y && \
	apt-get install -y cmake llvm clang

RUN export PATH=$PATH:$HOME/.cargo/bin && cargo build --$PROFILE
RUN rm src/*.rs

ADD . ./

# build the wallet app
RUN rm ./target/release/deps/baf-progressive-wallet*
RUN export PATH=$PATH:$HOME/.cargo/bin && cargo build --release


# ===== SECOND STAGE ======

ARG APP=/usr/src/app

RUN apt-get update \
    && apt-get install -y ca-certificates tzdata \
    && rm -rf /var/lib/apt/lists/*

EXPOSE 3000

# # TODO: should we be using UTC?
ENV TZ=Etc/UTC \
    APP_USER=appuser

RUN groupadd $APP_USER \
    && useradd -g $APP_USER $APP_USER \
    && mkdir -p ${APP}

COPY --from=builder /baf-progressive-wallet/target/release/baf-progressive-wallet ${APP}/baf-progressive-wallet

RUN chown -R $APP_USER:$APP_USER ${APP}

USER $APP_USER
WORKDIR ${APP}

CMD ["./rust-docker-web"]
ENV TZ=Etc/UTC \
    APP_USER=appuser

RUN groupadd $APP_USER \
    && useradd -g $APP_USER $APP_USER \
    && mkdir -p ${APP}

COPY --from=builder /baf-progressive-wallet/target/release/baf-progressive-wallet ${APP}/baf-progressive-wallet

RUN chown -R $APP_USER:$APP_USER ${APP}

USER $APP_USER
WORKDIR ${APP}

CMD ["./baf-progressive-wallet"]


# ************************


# # Following https://blog.logrocket.com/packaging-a-rust-web-service-using-docker/
# FROM rust:1.48 as builder
# # FROM rust:debian as builder

# # pseudo cache for dependencies
# RUN USER=root cargo new --bin baf-progressive-wallet
# WORKDIR ./baf-progressive-wallet
# COPY ./Cargo.toml ./Cargo.toml

# RUN cargo build --release
# RUN rm src/*.rs

# ADD . ./

# # build the wallet app
# RUN rm ./target/release/deps/baf-progressive-wallet*
# RUN cargo build --release


# FROM debian:buster-slim
# ARG APP=/usr/src/app

# RUN apt-get update \
#     && apt-get install -y ca-certificates tzdata \
#     && rm -rf /var/lib/apt/lists/*

# EXPOSE 3000

# # TODO: should we be using UTC?
# ENV TZ=Etc/UTC \
#     APP_USER=appuser

# RUN groupadd $APP_USER \
#     && useradd -g $APP_USER $APP_USER \
#     && mkdir -p ${APP}

# COPY --from=builder /baf-progressive-wallet/target/release/baf-progressive-wallet ${APP}/baf-progressive-wallet

# RUN chown -R $APP_USER:$APP_USER ${APP}

# USER $APP_USER
# WORKDIR ${APP}

# CMD ["./rust-docker-web"]