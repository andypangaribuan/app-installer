import { defineConfig } from "vite";

export default defineConfig({
  server: {
    proxy: {
      "/config": "http://localhost:8080",
      "/login": "http://localhost:8080",
      "/logout": "http://localhost:8080",
      "/api": "http://localhost:8080",
      "/public": "http://localhost:8080",
      "/manifest.plist": "http://localhost:8080",
      "/install-ios.html": "http://localhost:8080",
    },
  },
});
