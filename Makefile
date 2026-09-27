.PHONY: build test verify package docker-build docker-up demo checkstyle spotbugs pmd mutation clean

build:
	./mvnw clean compile

test:
	./mvnw clean test

verify:
	./mvnw clean verify

package:
	./mvnw clean package

docker-build:
	docker build -t secure-netpipe .

docker-up:
	docker compose up --build

demo:
	docker/demo.sh

checkstyle:
	./mvnw checkstyle:check

spotbugs:
	./mvnw spotbugs:check

pmd:
	./mvnw pmd:check

mutation:
	./mvnw org.pitest:pitest-maven:mutationCoverage

clean:
	./mvnw clean
