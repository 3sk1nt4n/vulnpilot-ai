#!/bin/bash
# Start Ollama server in background
ollama serve &
SERVER_PID=$!

# Wait for server to be ready
echo "⏳ Waiting for Ollama server..."
for i in $(seq 1 30); do
  if curl -sf http://localhost:11434/api/tags > /dev/null 2>&1; then
    echo "✅ Ollama server ready"
    break
  fi
  sleep 2
done

# Pull qwen2.5:3b if not already downloaded
if ! ollama list | grep -q "qwen2.5:3b"; then
  echo "📥 Pulling qwen2.5:3b (first time only, ~1.9GB)..."
  ollama pull qwen2.5:3b
  echo "✅ qwen2.5:3b ready"
else
  echo "✅ qwen2.5:3b already available"
fi

# Keep server running
wait $SERVER_PID
