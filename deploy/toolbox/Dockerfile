# ARGUS 工具镜像：只装"探测/验证"需要的工具，不装任何后渗透框架。
#
# 构建：
#   docker build -t argus-toolbox:latest deploy/toolbox
#
# 运行方式由 argus 自己决定（见 internal/toolbox/container.go），关键参数：
#   --rm --read-only --cap-drop ALL --security-opt no-new-privileges
#   --user 65534:65534 --pids-limit 256 --memory 512m --cpus 1
#   -v <任务工作目录>:/work:rw --entrypoint <工具>
#
# 注意：版本号请按你的环境固定并校验（供应链风险是真实存在的）。
FROM alpine:3.20

ARG NUCLEI_VER=3.3.5
ARG HTTPX_VER=1.6.9

RUN apk add --no-cache \
      nmap nmap-scripts curl bind-tools whois nikto ffuf python3 py3-pip unzip ca-certificates \
 && pip install --no-cache-dir --break-system-packages sqlmap \
 && curl -fsSL "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VER}/nuclei_${NUCLEI_VER}_linux_amd64.zip" -o /tmp/nuclei.zip \
 && unzip -o /tmp/nuclei.zip -d /usr/local/bin nuclei \
 && curl -fsSL "https://github.com/projectdiscovery/httpx/releases/download/v${HTTPX_VER}/httpx_${HTTPX_VER}_linux_amd64.zip" -o /tmp/httpx.zip \
 && unzip -o /tmp/httpx.zip -d /usr/local/bin httpx \
 && rm -f /tmp/nuclei.zip /tmp/httpx.zip \
 && nuclei -version >/dev/null 2>&1 || true

# 离线模板：容器通常没有外网，nuclei 必须用预置模板（-t /opt/pd-templates）
RUN mkdir -p /opt/pd-templates \
 && nuclei -update-templates -update-directory /opt/pd-templates -silent >/dev/null 2>&1 || true \
 && chmod -R a+rX /opt/pd-templates

# 工作目录由运行时以 -v 挂载，这里只占位并保证可写权限归 nobody
RUN mkdir -p /work && chown 65534:65534 /work

# 不设 USER：由 argus 用 --user 65534:65534 强制，避免镜像内 ENTRYPOINT 提权
WORKDIR /work
