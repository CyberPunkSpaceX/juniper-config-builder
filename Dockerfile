# syntax=docker/dockerfile:1
FROM python:3.12-slim AS build
WORKDIR /src
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip wheel --no-cache-dir --wheel-dir /wheels '.[web]'

FROM python:3.12-slim
LABEL org.opencontainers.image.source="https://github.com/CyberPunkSpaceX/switch-config-builder" \
      org.opencontainers.image.description="Multi-Vendor Switch Config Builder: web GUI that builds switch configs for Juniper, Arista, Cisco, Dell, Extreme, Fortinet, MikroTik, UniFi, Ruckus and HPE Aruba"
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN useradd --system --uid 10001 --no-create-home exbuilder \
 && mkdir -p /data && chown exbuilder /data
ENV EXB_DATA_DIR=/data HOME=/tmp
VOLUME ["/data"]
COPY --from=build /wheels /wheels
RUN pip install --no-cache-dir /wheels/*.whl && rm -rf /wheels
USER exbuilder
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/healthz').status==200 else 1)"
# Access logs are off on purpose: requests carry passwords and SNMP secrets.
# --preload runs first-start setup once, before the workers fork.
CMD ["gunicorn", "--bind", "0.0.0.0:8080", "--workers", "2", "--timeout", "300", "--preload", "exbuilder.web:create_app()"]
