FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Código, API, portal e configuração
COPY importer ./importer
COPY api ./api
COPY web ./web
COPY config ./config

RUN mkdir -p /app/data
ENV CONFIG_PATH=/app/config/config.yaml

# Padrão: importador em serviço. O serviço 'api' sobrescreve o command.
CMD ["python", "-m", "importer.run", "--loop"]
