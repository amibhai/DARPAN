# DARPAN Reflector Node — Hardened Cowrie Honeypot
FROM python:3.11-slim

ARG COWRIE_USER=cowrie
ARG COWRIE_UID=1000
ARG COWRIE_GID=1000

# System dependencies
RUN apt-get update -qq && \
    apt-get install -y --no-install-recommends \
        git \
        libssl-dev \
        libffi-dev \
        build-essential \
        python3-dev \
        libpython3-dev \
        curl \
        procps \
        authbind \
    && rm -rf /var/lib/apt/lists/*

# Create non-root cowrie user
RUN groupadd -g ${COWRIE_GID} ${COWRIE_USER} && \
    useradd -m -u ${COWRIE_UID} -g ${COWRIE_GID} \
            -d /cowrie -s /bin/bash ${COWRIE_USER}

# Clone Cowrie from source
WORKDIR /cowrie
RUN git clone --depth=1 https://github.com/cowrie/cowrie /cowrie/cowrie-src

# Install Cowrie Python requirements
WORKDIR /cowrie/cowrie-src
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir \
        anthropic \
        elasticsearch \
        python-dotenv \
        requests

# Create runtime directory structure
RUN mkdir -p \
        /cowrie/var/log/cowrie \
        /cowrie/var/lib/cowrie/downloads \
        /cowrie/var/lib/cowrie/tty \
        /cowrie/honeyfs \
        /cowrie/etc && \
    cp -r /cowrie/cowrie-src/honeyfs /cowrie/honeyfs-default

# Copy DARPAN custom configuration
COPY cowrie.cfg /cowrie/etc/cowrie.cfg
COPY userdb.txt /cowrie/etc/userdb.txt

# Copy custom command handler
COPY custom_commands.py /cowrie/cowrie-src/src/cowrie/commands/darpan_llm.py

# Copy honeyfs if it exists (built by generate_honeyfs.py)
COPY honeyfs/ /cowrie/honeyfs/

# Fix permissions — all owned by cowrie user
RUN chown -R ${COWRIE_USER}:${COWRIE_USER} /cowrie && \
    chmod -R 750 /cowrie && \
    chmod 770 /cowrie/var/log/cowrie && \
    chmod 770 /cowrie/var/lib/cowrie/downloads

# Create symlinks for Cowrie config
RUN ln -sf /cowrie/etc/cowrie.cfg /cowrie/cowrie-src/etc/cowrie.cfg && \
    ln -sf /cowrie/etc/userdb.txt /cowrie/cowrie-src/etc/userdb.txt && \
    ln -sf /cowrie/honeyfs /cowrie/cowrie-src/honeyfs

EXPOSE 2222 2223

HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD pgrep -f "twistd.*cowrie" > /dev/null || \
        pgrep -f "python.*cowrie" > /dev/null || exit 1

USER ${COWRIE_USER}
WORKDIR /cowrie/cowrie-src

ENTRYPOINT ["/bin/bash", "-c", \
    "exec python bin/cowrie start --nodaemon 2>&1"]
