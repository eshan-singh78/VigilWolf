#!/bin/bash

echo "Starting VigilWolf..."
echo ""

if ! command -v docker &> /dev/null; then
    echo "Docker is not installed. Please install Docker first."
    echo "Visit: https://docs.docker.com/get-docker/"
    exit 1
fi

if ! command -v docker-compose &> /dev/null; then
    echo "Docker Compose is not installed. Please install Docker Compose first."
    echo "Visit: https://docs.docker.com/compose/install/"
    exit 1
fi

if ! docker info &> /dev/null; then
    echo "Docker daemon is not running. Please start Docker first."
    exit 1
fi

echo "Docker is ready"
echo ""

echo "Building and starting containers..."
docker-compose up --build -d

echo ""
echo "Waiting for services to start..."
sleep 5

echo "Checking backend health..."
for i in {1..30}; do
    if curl -s http://localhost:8000/health > /dev/null 2>&1; then
        echo "Backend is ready!"
        break
    fi
    if [ $i -eq 30 ]; then
        echo "Backend health check timeout. Check logs with: docker-compose logs backend"
    fi
    sleep 2
done
