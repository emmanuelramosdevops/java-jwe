#Build
FROM --platform=linux/amd64 gradle:8.4-jdk17-alpine AS Build

WORKDIR /opt/app

COPY build.gradle settings.gradle .

COPY src src

RUN gradle bootJar -x test

# Run
FROM --platform=linux/amd64 openjdk:17-jdk-alpine

RUN \
    apk update && \
    apk upgrade

WORKDIR /opt

COPY --from=Build /opt/app/build/libs/*.jar /opt

RUN \
    adduser -D 1001

USER 1001

ENTRYPOINT ["sh", "-c", "java -jar /opt/*.jar"]