FROM python:3.9-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential gcc curl binutils \
  && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./ 
RUN pip install --upgrade pip && \
    if [ -f requirements.txt ]; then pip install -r requirements.txt; fi

RUN mkdir -p deployment_files/model
COPY server_files ./
COPY deployment_files/model/server.zip /app/deployment_files/model/
COPY deployment_files/model/report.json /app/deployment_files/model/
COPY run_inference.py ./

CMD ["python", "run_inference.py"]
