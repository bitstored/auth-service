FROM golang:alpine as source
WORKDIR /home/server
COPY . .
WORKDIR cmd/auth-service
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -mod vendor -o auth-service

FROM alpine as runner
LABEL name="bitstored/auth-service"
RUN apk --update add ca-certificates
COPY --from=source /home/server/cmd/auth-service/auth-service /home/auth-service
COPY --from=source /home/server/scripts/localhost.* /home/scripts/
WORKDIR /home
EXPOSE 4001
ENTRYPOINT [ "./auth-service" ]
