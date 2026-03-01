FROM node:18-slim

LABEL maintainer="Vegetarian Juice Shop"
LABEL description="Intentionally vulnerable web application for security testing"

# Install build tools for better-sqlite3 native compilation + network tools for pingability
RUN apt-get update && apt-get install -y \
    python3 \
    make \
    g++ \
    iputils-ping \
    dnsutils \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy package files
COPY package.json ./

# Install dependencies
RUN npm install --production

# Copy application source
COPY server/ ./server/
COPY frontend/ ./frontend/

# Create uploads directory
RUN mkdir -p uploads

# Expose port
EXPOSE 2212

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:2212/ || exit 1

# Run the application
CMD ["node", "server/app.js"]
