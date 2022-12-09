FROM golang:1.18-alpine

ARG VERSION="development-build"

ENV SERVER_PORT="8080"
ENV GIN_MODE=release
ENV JSON_LOGGING_ENABLED=true

# Provider ID to be used for veryfing VCs
ENV PROVIDER_ID="did:ebsi:myprovider"

# ISHARE RELATED
ENV ISHARE_ENABLED=true
ENV ISHARE_CERTIFICATE_PATH="/iShare/certificate.pem"
ENV ISHARE_KEY_PATH="/iShare/key.pem"
ENV ISHARE_CLIENT_ID="EU.EORI.MyDummyClient"
ENV ISHARE_AR_ID="EU.EORI.NL000000004"
ENV ISHARE_AUTHORIZATION_REGISTRY_URL="https://ar.isharetest.net"

# DB DEFAULTS

ENV MYSQL_HOST=localhost
ENV MYSQL_PORT=3306
ENV MYSQL_DATABASE=dsba
ENV MYSQL_USERNAME=root
ENV MYSQL_PASSWORD=password

WORKDIR /go/src/app
COPY ./ ./

RUN go get -d -v ./...
RUN go install -ldflags="-X 'github.com/fiware/dsba-pdp/http.Version=${VERSION}'" -v ./...

CMD ["dsba-pdp"]
