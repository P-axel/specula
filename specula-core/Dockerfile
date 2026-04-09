FROM python:3.11-slim

WORKDIR /app

# Utilisateur non-root — le container ne tourne pas en root
RUN groupadd -r specula && useradd -r -g specula specula

# Dépendances
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r /app/requirements.txt

COPY specula-core /app/specula-core

# Répertoire runtime pour la BDD SQLite
RUN mkdir -p /app/runtime/db && chown -R specula:specula /app

ENV PYTHONPATH=/app/specula-core

WORKDIR /app/specula-core

USER specula

EXPOSE 8000

CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "8000"]