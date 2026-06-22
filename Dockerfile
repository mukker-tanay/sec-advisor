# Use a lightweight python image
FROM python:3.10-slim

# Copy uv binary for rapid dependency building
COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PORT=7860

WORKDIR /app

# Copy dependency files
COPY pyproject.toml uv.lock ./

# Sync dependencies using uv
RUN uv sync --frozen --no-cache

# Copy the rest of the project files
COPY . .

# Generate the Qdrant local database during Docker build
RUN uv run python embed_and_store.py

# Hugging Face Spaces listen on port 7860 by default
EXPOSE 7860

# Command to launch Streamlit on HF Spaces port
CMD ["uv", "run", "streamlit", "run", "app.py", "--server.port=7860", "--server.address=0.0.0.0"]
