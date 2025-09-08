# app/Dockerfile
FROM python:3.9-slim-buster

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source code
COPY src/ .

# Expose the port the Flask app runs on
EXPOSE 5000

# Command to run the application
CMD ["python", "main.py"]