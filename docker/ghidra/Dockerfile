FROM python:3.12-slim@sha256:78387bc3881b8273120a12ebe6c1ab22b018ccc2c9adf565ae1ac9b536e184ea

ARG GHIDRA_VERSION=12.1.3
ARG GHIDRA_BUILD_DATE=20260817
ARG GHIDRA_TAG=Ghidra_12.1.3_build
ARG GHIDRA_SHA256=93a5d11a9ad510622acaaf908c556a7b9b764d338e78a7567f3689bf5081fd54
ARG JDK_URL=https://github.com/adoptium/temurin21-binaries/releases/download/jdk-21.0.12.1%2B1/OpenJDK21U-jdk_x64_linux_hotspot_21.0.12.1_1.tar.gz
ARG JDK_SHA256=ce79869e1307ed8ee1e2baa86a412b1eb5b75d10a01006d788a6f968bcfaee94
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl unzip \
    && curl -fsSL "${JDK_URL}" -o /tmp/jdk.tar.gz \
    && echo "${JDK_SHA256}  /tmp/jdk.tar.gz" | sha256sum -c - \
    && mkdir -p /opt/java \
    && tar -xzf /tmp/jdk.tar.gz --strip-components=1 -C /opt/java \
    && curl -fsSL "https://github.com/NationalSecurityAgency/ghidra/releases/download/${GHIDRA_TAG}/ghidra_${GHIDRA_VERSION}_PUBLIC_${GHIDRA_BUILD_DATE}.zip" -o /tmp/ghidra.zip \
    && echo "${GHIDRA_SHA256}  /tmp/ghidra.zip" | sha256sum -c - \
    && unzip -q /tmp/ghidra.zip -d /opt \
    && mv "/opt/ghidra_${GHIDRA_VERSION}_PUBLIC" /opt/ghidra \
    && rm -f /tmp/ghidra.zip /tmp/jdk.tar.gz \
    && apt-get purge -y --auto-remove curl unzip \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --uid 10001 --create-home --shell /usr/sbin/nologin analyzer \
    && mkdir -p /opt/ai-signal-scripts \
    && chown -R 10001:10001 /opt/ai-signal-scripts

COPY --chown=10001:10001 GhidraExport.java /opt/ai-signal-scripts/GhidraExport.java
USER 10001:10001
ENV HOME=/tmp/home JAVA_HOME=/opt/java PATH=/opt/java/bin:$PATH GHIDRA_HEADLESS_MAXMEM=4G
ENTRYPOINT ["/opt/ghidra/support/analyzeHeadless"]
