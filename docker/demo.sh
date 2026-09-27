#!/bin/bash
set -e

echo "Building Docker images..."
docker compose build

echo "Starting server..."
docker compose up -d netpipe-server

echo "Waiting for server to be ready..."
sleep 5

echo "Starting client and sending test message..."
echo "Hello from secure netpipe test" | docker compose run --rm netpipe-client

echo "Demo completed successfully!"
exit 0
