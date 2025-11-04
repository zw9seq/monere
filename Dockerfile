# Imagen base ligera con Python 3.11
FROM python:3.11-slim

# Evita problemas de buffering con logs
ENV PYTHONUNBUFFERED=1

# Establece el directorio de trabajo
WORKDIR /app

# Instala dependencias del sistema (por si tu app usa ping, nmap, etc.)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        iputils-ping \
        net-tools \
        nmap \
        tcpdump \
        iproute2 \
        gcc \
        g++ \
        make \
        libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Copia el código y los requisitos
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copiamos el código principal y la configuración
COPY app ./app
COPY config ./config

# Expone el puerto en el que correrá FastAPI
EXPOSE 8000

# Comando de inicio
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
