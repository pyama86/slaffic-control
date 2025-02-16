FROM golang:latest as builder
ADD . /opt/slaffic-control
WORKDIR /opt/slaffic-control/
ENV CGO_ENABLED=0
RUN GOOS=linux make build
RUN mkdir -p /opt/slaffic-control/db

FROM scratch
COPY --from=builder /opt/slaffic-control/bin/slaffic-control /bin/slaffic-control
COPY --from=builder /opt/slaffic-control/db /opt/slaffic-control/db
EXPOSE 3000
ENV DB_PATH=/opt/slaffic-control/db/slaffic.db
CMD ["/bin/slaffic-control"]
