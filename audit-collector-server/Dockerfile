# 監査ログ収集サーバー（JDK 標準のみ＋PostgreSQL JDBC ドライバー）
FROM eclipse-temurin:21-jdk-alpine AS builder
WORKDIR /build
COPY audit-collector-server/src/main ./src/main
RUN mkdir -p out lib \
 && wget -q -O lib/postgresql.jar https://repo1.maven.org/maven2/org/postgresql/postgresql/42.7.4/postgresql-42.7.4.jar \
 && find src/main -name "*.java" > sources.txt \
 && javac -encoding UTF-8 -d out @sources.txt

FROM eclipse-temurin:21-jre-alpine
RUN addgroup -S app && adduser -S app -G app && mkdir -p /data && chown app:app /data
USER app
WORKDIR /app
COPY --from=builder /build/out ./classes
COPY --from=builder /build/lib ./lib
ENV COLLECTOR_PORT=8081 ANCHOR_FILE=/data/chain-anchors.jsonl
EXPOSE 8081
CMD ["java", "-cp", "/app/classes:/app/lib/*", "com.audit.collector.web.CollectorServer"]
