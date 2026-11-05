#!/bin/bash
cd "$(dirname "$0")"
PORT=8768

if lsof -i :$PORT -t >/dev/null 2>&1; then
  echo "Spark Meeting already running on port $PORT"
  open "http://localhost:$PORT"
  exit 0
fi

if [ -d "../m365-mcp-venv" ]; then
  PYTHON="../m365-mcp-venv/bin/python3"
else
  PYTHON="python3"
fi

echo "Starting Spark Meeting on http://localhost:$PORT ..."
"$PYTHON" server.py &
SERVER_PID=$!

for i in $(seq 1 8); do
  sleep 1
  if curl -s "http://localhost:$PORT" >/dev/null 2>&1; then
    echo "Ready."
    open "http://localhost:$PORT"
    echo "Press Ctrl+C to stop."
    wait $SERVER_PID
    exit 0
  fi
done

echo "Server failed to start."
kill $SERVER_PID 2>/dev/null
exit 1
