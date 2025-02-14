FROM golang:latest as builder
ADD . /opt/slaffic-control
WORKDIR /opt/slaffic-control/
ENV CGO_ENABLED=0
RUN GOOS=linux make build

FROM scratch
COPY --from=builder /opt/slaffic-control/bin/slaffic-control /bin/slaffic-control
EXPOSE 3000
CMD ["/bin/slaffic-control"]
