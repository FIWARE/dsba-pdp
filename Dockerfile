FROM golang:1.18-alpine

ENV SERVER_PORT="8080"
ENV GIN_MODE=release
ENV JSON_LOGGING_ENABLED=true

# ISHARE RELATED
ENV ISHARE_ENABLED=true
ENV ISHARE_CERTIFICATE_PATH="/iShare/certificate.pem"
ENV ISHARE_KEY_PATH="/iShare/key.pem"
ENV ISHARE_CLIENT_ID="EU.EORI.MyDummyClient"
ENV ISHARE_AR_ID="EU.EORI.NL000000004"
ENV ISHARE_AUTHORIZATION_REGISTRY_URL="https://ar.isharetest.net"

RUN mkdir /iShare

WORKDIR /go/src/app
COPY ./ ./

RUN go get -d -v ./...
RUN go install -v ./...

CMD ["dsba-pdp"]

