FROM golang:1.27.2-bookworm AS core
ENV CGO_ENABLED=0
RUN go mod download github.com/sagernet/sing-box@v1.14.3
RUN cp -a /go/pkg/mod/github.com/sagernet/sing-box@v1.14.3 /src && chmod -R u+w /src
COPY core-patches/connection-user.patch /tmp/connection-user.patch
WORKDIR /src
RUN git apply /tmp/connection-user.patch && go build -tags with_quic,with_utls,with_v2ray_api,with_clash_api \
    -ldflags '-s -w -X github.com/sagernet/sing-box/constant.Version=1.14.3' \
    -o /go/bin/sing-box ./cmd/sing-box

FROM python:3.13-slim-bookworm
RUN useradd --uid 10001 --create-home panel && mkdir /data && chown panel:panel /data
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY --from=core /go/bin/sing-box /usr/local/bin/sing-box
COPY panel ./panel
ENV PANEL_DATA=/data PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
USER 10001:10001
CMD ["uvicorn", "panel.app:app", "--host", "127.0.0.1", "--port", "18889", "--no-access-log"]
