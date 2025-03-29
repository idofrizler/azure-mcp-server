# Use Python 3.12 slim image
FROM python:3.12-slim-bookworm

# Set working directory
WORKDIR /app

# Copy project files
COPY . .

# Install dependencies and the project
RUN pip install -e .

# Set environment variables
ENV PYTHONUNBUFFERED=1

# Set the entrypoint
ENTRYPOINT ["azure-mcp-server"]

# Label the image
LABEL maintainer="idofrizler" \
      description="Azure MCP Server" \
      version="1.0.0"
