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

COPY kenya_agri.csv ./
COPY training.py ./

CMD ["python", "training.py"]
