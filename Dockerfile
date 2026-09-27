# Build stage
FROM maven:3.9-eclipse-temurin-17 AS builder
WORKDIR /build

# Cache dependencies
COPY pom.xml .
RUN mvn dependency:go-offline

# Copy source and build
COPY src ./src
RUN mvn clean package -DskipTests

# Runtime stage
FROM eclipse-temurin:17-jre
WORKDIR /app

# Create non-root user
RUN useradd -r -M -s /bin/false netpipe && \
    chown -R netpipe:netpipe /app
USER netpipe

# Expose default port
EXPOSE 2206

# Copy jar
COPY --from=builder --chown=netpipe:netpipe /build/target/secure-netpipe-1.0.0.jar /app/secure-netpipe.jar

# Entrypoint setup
ENTRYPOINT ["java", "-cp", "/app/secure-netpipe.jar"]
CMD ["se.ermia.netpipe.server.NetPipeServer"]
