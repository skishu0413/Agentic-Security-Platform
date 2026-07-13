FROM python:3.11-slim

WORKDIR /app
COPY . /app
RUN pip install --no-cache-dir -r requirements.txt
RUN chmod +x start.sh deploy.sh

EXPOSE 8000
CMD ["uvicorn", "app:app", "--host", "127.0.0.1", "--port", "8000"]
