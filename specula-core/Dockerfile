FROM python:3.11-slim

WORKDIR /app

# Installation des dépendances
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r /app/requirements.txt

# On ne copie QUE le code source (Tests ignorés)
COPY specula-core /app/specula-core

ENV PYTHONPATH=/app/specula-core
WORKDIR /app/specula-core

EXPOSE 8000

CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000"]