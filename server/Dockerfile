FROM python:3.12-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy server + dashboard
COPY server.py .
COPY dashboard.html .

# Reports directory (mounted as volume in production)
RUN mkdir -p reports

EXPOSE 8000

CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8000"]
