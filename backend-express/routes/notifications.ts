import express from "express";
import { authenticate } from "../middleware/auth";
import { NotificationService } from "../services/notificationService";

const router = express.Router();

// GET /api/notifications - list current user's notifications
router.get("/", authenticate, (req, res) => {
  const list = NotificationService.listForUser(req.user!.id);
  return res.json(list);
});

// PUT /api/notifications/:id/read - mark one as read
router.put("/:id/read", authenticate, (req, res) => {
  const ok = NotificationService.markRead(req.user!.id, req.params.id);
  if (!ok) return res.status(404).json({ error: "Notification not found" });
  return res.json({ ok: true });
});

// PUT /api/notifications/read-all - mark all as read
router.put("/read-all", authenticate, (req, res) => {
  const count = NotificationService.markAllRead(req.user!.id);
  return res.json({ ok: true, count });
});

// POST /api/notifications/test-email - send SMTP test to current user
router.post("/test-email", authenticate, async (req, res) => {
  try {
    const { EmailService } = await import("../services/emailService");
    const result = await EmailService.sendNotificationEmail(
      req.user!.email,
      "Test SMTP",
      `Ceci est un email de test envoyé le ${new Date().toLocaleString("fr-FR")}.`,
    );
    return res.json({
      ok: true,
      messageId: result.messageId,
      previewUrl: (result as any).previewUrl || null,
    });
  } catch (e) {
    return res.status(500).json({ ok: false, error: (e as Error).message });
  }
});

export default router;
