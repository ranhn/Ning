# ARGUS 运行镜像：非 root、只读根、零外部依赖（纯标准库 Go）
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o /out/argus ./cmd/argus

FROM alpine:3.20
RUN apk add --no-cache ca-certificates && adduser -D -u 10001 -h /data argus
COPY --from=build /out/argus /usr/local/bin/argus
USER 10001:10001
WORKDIR /data
EXPOSE 8787
ENTRYPOINT ["/usr/local/bin/argus"]
CMD ["serve", "-addr", ":8787", "-data", "/data"]
