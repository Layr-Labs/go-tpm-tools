FROM alpine:3.19

RUN apk --no-cache add ca-certificates

COPY kms /kms

EXPOSE 8080

ENTRYPOINT ["/kms"]
