# ========== 构建阶段 ==========
FROM golang:1.22-alpine AS builder

WORKDIR /app
COPY go.mod go.sum* ./
RUN go mod download 2>/dev/null || true
COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o neokit .

# ========== 运行阶段 ==========
FROM alpine:3.19

RUN apk add --no-cache ca-certificates tzdata

COPY --from=builder /app/neokit /neokit
COPY --from=builder /app/api/public /api/public

EXPOSE 8080

CMD ["/neokit"]
