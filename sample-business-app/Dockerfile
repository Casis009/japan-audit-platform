# 監査センサーを組み込んだデモ業務アプリ（依存ライブラリなし）
FROM eclipse-temurin:21-jdk-alpine AS builder
WORKDIR /build
COPY servlet-api-lite/src/main ./servlet-api-lite/src/main
COPY audit-core-rule/src/main ./audit-core-rule/src/main
COPY audit-sensor/src/main ./audit-sensor/src/main
COPY sample-business-app/src/main ./sample-business-app/src/main
RUN mkdir -p out \
 && find . -path "*/src/main/*" -name "*.java" > sources.txt \
 && javac -encoding UTF-8 -d out @sources.txt

FROM eclipse-temurin:21-jre-alpine
RUN addgroup -S app && adduser -S app -G app && mkdir -p /spool && chown app:app /spool
USER app
WORKDIR /app
COPY --from=builder /build/out ./classes
ENV APP_PORT=8080 SPOOL_PATH=/spool
EXPOSE 8080
CMD ["java", "-cp", "/app/classes", "com.audit.demo.DemoBusinessApplication"]
