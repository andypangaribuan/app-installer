# Running the Project

This project can be run in several ways depending on your environment.

## 1. Using Devbox (Recommended for Local Development)

If you have [Devbox](https://www.jetpack.io/devbox/docs/installing_devbox/) installed:

1.  **Initialize the environment:**

    ```bash
    devbox shell
    ```

    _This will automatically set up a Python virtual environment, install dependencies from `requirements.txt`, and run `npm install`._

2.  **Run the server:**

    ```bash
    devbox run server
    ```

    The server will be available at `http://localhost:8080`.

3.  **Run frontend dev (Vite):**
    ```bash
    devbox run dev
    ```

## 2. Using Docker (Recommended for Production/Simulation)

### Docker Compose

The easiest way to run the full stack with persistent storage:

```bash
docker-compose up -d --build
```

### Manual Docker Build

```bash
# Build
docker build -t app-installer .

# Run
docker run -p 8080:8080 app-installer
```

## 3. Manual Local Run (Standard Python)

If you prefer not to use Devbox:

1.  **Setup Virtual Environment:**

    ```bash
    python -m venv .venv
    source .venv/bin/activate  # On Windows use `.venv\Scripts\activate`
    ```

2.  **Install Dependencies:**

    ```bash
    pip install -r requirements.txt
    npm install
    ```

3.  **Run Server:**
    ```bash
    python server.py
    ```

## Configuration

Ensure you have a `.env` file in the root directory. You can use the following variables:

- `ADMIN_EMAILS`: Comma-separated list of admin emails.
- `SUPER_ADMIN_EMAILS`: Comma-separated list of super admin emails.
- `SECURE_LOGIN`: `true` or `false` (default: `true`).
- `PUSH_NOTIFICATION_URL`: URL for push notifications.
- `PUSH_NOTIFICATION_HEADER`: Secret header for push notifications.
- `APP_INSTALLER_URL`: The base URL where the installer is hosted.
