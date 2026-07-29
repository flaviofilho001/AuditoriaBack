FROM python:3.11-slim

WORKDIR /app

# Instala dependências do sistema
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copia requirements e instala dependências Python
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copia todo o código-fonte e a base de conhecimento
COPY . .

# Porta padrão fornecida pelo Railway via $PORT
ENV PORT=8000
EXPOSE 8000

CMD ["sh", "-c", "uvicorn src.presentation.api.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
