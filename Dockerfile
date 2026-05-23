# Use a lightweight Python base image
FROM python:3.10-slim

# Create a non-privileged user (Hugging Face Spaces runs as UID 1000)
RUN useradd -m -u 1000 user

# Set the working directory inside the container
WORKDIR /app

# Copy the requirements file first for caching optimization
COPY --chown=user requirements.txt .

# Install dependencies (on Linux, pywin32 will be skipped automatically)
RUN pip install --no-cache-dir -r requirements.txt

# Copy the remaining project files
COPY --chown=user . .

# Set environment variables
ENV PORT=7860
ENV FLASK_APP=app.py
ENV FLASK_ENV=production

# Switch to the non-root user
USER user

# Expose the default port
EXPOSE 7860

# Launch the Flask application using Gunicorn for production scalability
CMD ["gunicorn", "--bind", "0.0.0.0:7860", "app:app", "--workers", "2", "--threads", "4", "--timeout", "120"]
