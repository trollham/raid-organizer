FROM lukemathwalker/cargo-chef:latest-rust-1-slim-buster as chef
WORKDIR /raid-organizer

FROM chef as planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef as builder
COPY --from=planner /raid-organizer/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json
COPY . .
RUN cargo build --release --bin raid-organizer

FROM debian:buster-slim as runtime
WORKDIR /raid-organizer
COPY --from=builder /raid-organizer/target/release/raid-organizer /usr/local/bin
EXPOSE 3000
ENTRYPOINT ["/usr/local/bin/raid-organizer"]

