FROM node:18-alpine

LABEL maintainer="Vegetarian Juice Shop"
LABEL description="Intentionally vulnerable web application for security testing"

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
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:3000/ || exit 1

# Run the application
CMD ["node", "server/app.js"]
