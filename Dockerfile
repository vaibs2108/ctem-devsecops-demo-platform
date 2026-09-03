FROM python:3.11-slim

# Create a non-root user with UID 1000 (Required for Hugging Face Spaces)
RUN useradd -m -u 1000 user

WORKDIR /app

# Install system dependencies required for FAISS and compiling packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    git \
    libgomp1 \
    && rm -rf /var/lib/apt/lists/*

# Copy project files with ownership given to the non-root user
COPY --chown=user:user . /app/

# Ensure the data directory exists and is owned by the user
RUN mkdir -p /app/data && chown -R user:user /app

# Switch to the non-root user
USER user

# Ensure local bin is in PATH for pip installed binaries
ENV PATH="/home/user/.local/bin:$PATH"

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# Hugging Face Spaces uses port 7860
EXPOSE 7860

HEALTHCHECK CMD curl --fail http://localhost:7860/_stcore/health || exit 1

ENTRYPOINT ["streamlit", "run", "main.py", "--server.port=7860", "--server.address=0.0.0.0"]
