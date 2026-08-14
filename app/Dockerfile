FROM python:3.13-alpine
WORKDIR /app
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
RUN apk add --no-cache curl tzdata
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN addgroup -S kingdom && adduser -S -G kingdom kingdom && mkdir -p /data && chown -R kingdom:kingdom /data /app
USER kingdom
EXPOSE 8080
CMD ["uvicorn","main:app","--host","0.0.0.0","--port","8080"]
