FROM golang:1.27.4@sha256:205c7636d74e0ffbe3d007162df7d74f859f5a8c8322dfb9f907977686c126cf AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/airlock ./cmd/airlock \
    && mkdir /out/data

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /out/airlock /airlock
# The SQLite store defaults to the working directory, so it must be writable.
COPY --from=build --chown=65532:65532 /out/data /data
WORKDIR /data
VOLUME /data
ENV AIRLOCK_LISTEN_ADDR=:8080
EXPOSE 8080
ENTRYPOINT ["/airlock"]
CMD ["serve"]
