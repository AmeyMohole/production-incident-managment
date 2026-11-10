FROM python:3.12-slim

RUN useradd --create-home app
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .
USER app
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s CMD python -c "import urllib.request as u; u.urlopen('http://localhost:8000/health')"

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
