/// <reference types="vitest" />
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react-swc";
import path from "path";

export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./frontend"),
      "@shared": path.resolve(__dirname, "./shared"),
    },
  },
  test: {
    environment: "node", // Changé temporairement pour éviter l'erreur jsdom
    globals: true,
    setupFiles: ["./test/setup.ts"],
    coverage: {
      provider: "v8",
      reporter: ["text", "json", "html"],
      exclude: [
        "node_modules/",
        "dist/",
        "coverage/",
        "**/*.d.ts",
        "**/*.config.{js,ts}",
        "**/test/**",
      ],
    },
    include: [
      "frontend/**/*.{test,spec}.{js,ts,tsx}",
      "backend-express/**/*.{test,spec}.{js,ts}",
      "shared/**/*.{test,spec}.{js,ts}",
    ],
    exclude: ["node_modules/", "dist/", "coverage/"],
  },
});
