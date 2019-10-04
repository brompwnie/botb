FROM golang:latest as builder
RUN mkdir /app 
ADD . /app/ 
WORKDIR /app 
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o "botb_$(uname -m)" . \
  && ln -s "botb_$(uname -m)" botb

FROM scratch
COPY --from=builder /app/botb* /
CMD ["/botb"]
