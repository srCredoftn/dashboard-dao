#!/usr/bin/env tsx
import { createServer } from "./index.js";
import { logger } from "./utils/logger.js";

const app = createServer();
const PORT = process.env.PORT || 3001;

app.listen(PORT, () => {
  logger.info(`🚀 Secure backend server running on port ${PORT}`, "SERVER");
  logger.info(`🔐 Security features enabled:`, "SERVER");
  logger.info(`  ✅ Password hashing with bcrypt`, "SERVER");
  logger.info(`  ✅ JWT tokens with expiration`, "SERVER");
  logger.info(`  ✅ Rate limiting`, "SERVER");
  logger.info(`  ✅ Input validation`, "SERVER");
  logger.info(`  ✅ CORS protection`, "SERVER");
  logger.info(`  ✅ Helmet security headers`, "SERVER");
  logger.info(`  ✅ Audit logging`, "SERVER");
  logger.info(
    `📡 API endpoints available at http://localhost:${PORT}/api/`,
    "SERVER",
  );
});

// Graceful shutdown
process.on("SIGTERM", () => {
  logger.info("🔄 SIGTERM received, shutting down gracefully", "SERVER");
  process.exit(0);
});

process.on("SIGINT", () => {
  logger.info("🔄 SIGINT received, shutting down gracefully", "SERVER");
  process.exit(0);
});
