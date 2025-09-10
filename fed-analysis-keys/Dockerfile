FROM python:3.9-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_EXTRA_INDEX_URL=https://download.pytorch.org/whl/cpu

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates age \
  && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
COPY constraints.txt .
RUN pip install --no-cache-dir --only-binary=:all: --prefer-binary \
    -r requirements.txt -c constraints.txt
RUN pip install --no-cache-dir --no-binary=ioctl-opt aws_nsm_interface

RUN mkdir -p /app/policy
COPY age_files/recipients/recipients.json /app/policy/recipients.json
RUN chmod 0444 /app/policy/recipients.json

# Accept and expose the JSON file hash
ARG RECIPIENTS_JSON_SHA256
ENV RECIPIENTS_JSON_SHA256=${RECIPIENTS_JSON_SHA256}

RUN mkdir -p deployment_files/model
COPY deployment_files/model/client.zip /app/deployment_files/model/
COPY keys-enclave.py .

CMD ["sh", "-c", "exec python3 /app/keys-enclave.py > /dev/console 2>&1"]
