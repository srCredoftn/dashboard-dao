import express from "express";
import { daoStorage } from "../data/daoStorage";
import { NotificationService } from "../services/notificationService";
import { AuthService } from "../services/authService";
import { getIdempotency, setIdempotency } from "../utils/idempotency";

// Factory that accepts a setter for the runtime bootId
export default function createAdminRoutes(setBootId: (id: string) => string) {
  const router = express.Router();

  // POST /api/admin/reset-app
  // Body: { rotateBootId?: boolean, seedDaos?: boolean }
  router.post("/reset-app", async (req, res) => {
    try {
      // In production, require an admin token. In development, allow local unauthenticated resets.
      if (process.env.NODE_ENV === "production") {
        // Require Authorization header
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith("Bearer ")) {
          return res.status(403).json({ error: "Forbidden: missing token" });
        }
        const token = authHeader.substring(7);
        const { AuthService } = await import("../services/authService");
        const verified = await AuthService.verifyToken(token);
        if (!verified || verified.role !== "admin") {
          return res.status(403).json({ error: "Forbidden: invalid token" });
        }
      }

      const { rotateBootId = true, seedDaos = false } = req.body || {};

      // Clear server-side data (DB or in-memory)
      try {
        const { DaoService } = await import("../services/daoService");
        await DaoService.clearAll();
      } catch (e) {
        // Fallback to daoStorage clear if DaoService clear fails
        try {
          daoStorage.clearAll(Boolean(seedDaos));
        } catch (_) {}
      }

      NotificationService.clearAll();

      // Reset auth users and sessions to defaults
      await AuthService.reinitializeUsers();
      await AuthService.clearAllSessions();

      // Optionally rotate boot id to force frontend clients to purge local storage
      let newBootId: string | null = null;
      if (rotateBootId) {
        const generated = Math.random().toString(36).slice(2, 14);
        newBootId = setBootId(generated);
      }

      return res.json({ ok: true, bootId: newBootId });
    } catch (e) {
      return res.status(500).json({ ok: false, error: (e as Error).message });
    }
  });

  // GET /api/admin/sessions - list active sessions (dev: unauth, prod: admin JWT)
  router.get("/sessions", async (req, res) => {
    try {
      if (process.env.NODE_ENV === "production") {
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith("Bearer ")) {
          return res.status(403).json({ error: "Forbidden: missing token" });
        }
        const token = authHeader.substring(7);
        const { AuthService } = await import("../services/authService");
        const verified = await AuthService.verifyToken(token);
        if (!verified || verified.role !== "admin") {
          return res.status(403).json({ error: "Forbidden: invalid token" });
        }
      }
      const { AuthService } = await import("../services/authService");
      const sessions = await AuthService.listActiveSessions();
      return res.json({ sessions, count: sessions.length });
    } catch (e) {
      return res.status(500).json({ ok: false, error: (e as Error).message });
    }
  });

  // POST /api/admin/revoke-session - revoke a specific token
  router.post("/revoke-session", async (req, res) => {
    try {
      if (process.env.NODE_ENV === "production") {
        const authHeader = req.headers.authorization;
        if (!authHeader || !authHeader.startsWith("Bearer ")) {
          return res.status(403).json({ error: "Forbidden: missing token" });
        }
        const token = authHeader.substring(7);
        const { AuthService } = await import("../services/authService");
        const verified = await AuthService.verifyToken(token);
        if (!verified || verified.role !== "admin") {
          return res.status(403).json({ error: "Forbidden: invalid token" });
        }
      }

      const { token: tokenToRevoke } = req.body || {};
      if (!tokenToRevoke || typeof tokenToRevoke !== "string") {
        return res.status(400).json({ error: "token is required in body" });
      }

      const { AuthService } = await import("../services/authService");
      await AuthService.logout(tokenToRevoke);
      return res.json({ ok: true, revoked: tokenToRevoke });
    } catch (e) {
      return res.status(500).json({ ok: false, error: (e as Error).message });
    }
  });

  // DELETE /api/admin/delete-last-dao - delete the most recently created DAO (admin + super admin password)
  router.delete("/delete-last-dao", async (req, res) => {
    try {
      const idempKey = (req.header("x-idempotency-key") || "").trim();
      if (idempKey) {
        const cached = getIdempotency(idempKey);
        if (cached) return res.json(cached);
      }

      const authHeader = req.headers.authorization;
      if (!authHeader || !authHeader.startsWith("Bearer ")) {
        return res.status(403).json({ error: "Forbidden: missing token" });
      }
      const token = authHeader.substring(7);
      const { AuthService } = await import("../services/authService");
      const verified = await AuthService.verifyToken(token);
      if (!verified || verified.role !== "admin") {
        return res.status(403).json({ error: "Forbidden: invalid token" });
      }

      // Require the current super admin password for destructive action
      const pwd = (req.body?.password || "").toString();
      if (!pwd) {
        return res.status(400).json({ error: "Password is required" });
      }
      const superAdmin = AuthService.getSuperAdmin();
      if (!superAdmin) {
        return res.status(403).json({ error: "No super admin configured" });
      }
      const valid = await AuthService.verifyPasswordById(superAdmin.id, pwd);
      if (!valid) {
        return res
          .status(403)
          .json({ error: "Invalid password", code: "INVALID_PASSWORD" });
      }

      const { DaoService } = await import("../services/daoService");
      const last = await DaoService.getLastCreatedDao();
      if (!last) {
        return res
          .status(404)
          .json({ error: "No DAO to delete", code: "NO_DAO" });
      }

      const ok = await DaoService.deleteDao(last.id);
      if (!ok) {
        return res
          .status(404)
          .json({ error: "DAO not found", code: "DAO_NOT_FOUND" });
      }

      try {
        NotificationService.broadcast(
          "dao_deleted",
          "DAO supprimé",
          `${last.numeroListe} – ${last.objetDossier}`,
          { daoId: last.id },
        );
        const { EmailService } = await import("../services/emailService");
        const users = await AuthService.getAllUsers();
        await EmailService.sendBulkNotification(
          users.map((u) => u.email),
          "DAO supprimé",
          `Le DAO ${last.numeroListe} a été supprimé de la plateforme.`,
        );
      } catch (_) {}

      const response = { deletedId: last.id, numeroListe: last.numeroListe };
      if (idempKey) setIdempotency(idempKey, response);

      return res.json(response);
    } catch (e) {
      return res.status(500).json({ ok: false, error: (e as Error).message });
    }
  });

  return router;
}
