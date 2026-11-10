FROM python:3.12-slim

RUN useradd --create-home app
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
USER app

CMD ["python", "-u", "worker.py"]
