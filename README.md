# App Installer Website

A premium, dynamic web application used to serve Android APKs and iOS IPAs (Ad-Hoc) with automatic OS detection and version selection.

## Features

- **Auto OS Detection**: Detects iOS vs Android.
- **Dynamic Manifest**: Generates iOS `manifest.plist` on-the-fly for ad-hoc installation.
- **Environment Selection**: Filter by **PROD**, **RC**, or **STG**.
- **Version History**: Select from a list of available versions defined in JSON.

## Prerequisites

- Docker & Docker Compose
- Or Python 3.x (to run locally without Docker)

## How to Build and Run (Docker)

### 1. Build the Image

To build the Docker image manually:

```bash
docker build --no-cache -t app-installer:x.x .
```

### 2. Run the Container

To run the container mapping port 8080:

```bash
docker run -p 8080:8080 app-installer
```

### 3. Using Docker Compose (Recommended)

This method is preferred as it maps the `public/downloads` directory, allowing you to add APK/IPA files without rebuilding the image.

**Start the service:**

```bash
docker-compose up -d --build
```

**Stop the service:**

```bash
docker-compose down
```

The website will be accessible at: `http://localhost:8080`

## Adding New Versions

1.  **Upload Files**: Place `.apk` files in `public/downloads/apk/` and `.ipa` files in `public/downloads/ipa/`.
2.  **Update JSON**: Edit `public/android_versions.json` or `public/ios_versions.json` to include the new version details.
    *   **Android**:
        ```json
        {
          "appName": "App Name",
          "version": "1.0.0",
          "date": "2025-01-01",
          "apkFile": "filename.apk",
          "environment": "prod"
        }
        ```
    *   **iOS**:
        ```json
        {
          "appName": "App Name",
          "version": "1.0.0",
          "date": "2025-01-01",
          "ipaFile": "filename.ipa",
          "bundleId": "com.example.app",
          "environment": "prod"
        }
        ```

## HTTPS Requirement (iOS)

For iOS Ad-Hoc installation to work on a real device, the server **MUST** be served over HTTPS.
- In **Production**: Put this container behind a reverse proxy (Nginx, Traefik, AWS ALB) with a valid SSL certificate.
- In **Local Development**: You can use tunneling tools like `ngrok` or `localtunnel` to expose port 8080 over HTTPS.


## TODO

- [x] Add Release Notes / Changelog
- [x] Download Analytics Dashboard
- [ ] Auto-Cleanup / Retention Policy 
   Mobile builds (APKs/IPAs) are large. Over time, your server storage will fill up with obsolete builds.
   Implementation: 
   - Add a setting in app_config.json for "Retention Limit" (e.g., Keep only the last 5 builds per environment or Delete builds older than 30 days).
   - Create a background task or an admin button to "Purge Old Builds".
  Why: Prevents server crashes due to disk space exhaustion and keeps the UI clean
