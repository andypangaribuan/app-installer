# Use an official Python runtime as a parent image
FROM python:3.14.2-alpine3.23

# Set the working directory in the container
WORKDIR /app

# Install required system dependencies for Pillow
RUN apk add --no-cache \
    jpeg-dev \
    zlib-dev \
    freetype-dev \
    lcms2-dev \
    openjpeg-dev \
    tiff-dev \
    tk-dev \
    tcl-dev

# Install Python packages
RUN pip install --no-cache-dir qrcode pillow

# Copy the current directory contents into the container at /app
COPY . /app

# Make port 8080 available to the world outside this container
EXPOSE 8080

# Run server.py when the container launches
CMD ["python", "server.py"]
