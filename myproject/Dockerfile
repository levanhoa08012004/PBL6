# Base image Python
FROM python:3.11-slim

# Thiết lập working directory
WORKDIR /app

# Copy file requirements và cài dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy toàn bộ code dự án vào container
COPY . .

# Thiết lập biến môi trường
ENV PYTHONUNBUFFERED=1
ENV PORT=8080

# Expose port (Railway dùng biến $PORT khi run container)
EXPOSE 8080

# Chạy Gunicorn
CMD ["gunicorn", "myproject.wsgi:application", "--bind", "0.0.0.0:8080"]
