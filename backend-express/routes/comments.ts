import express from "express";
import { CommentService } from "../services/commentService";
import { authenticate } from "../middleware/auth";
import { getIdempotency, setIdempotency } from "../utils/idempotency";

const router = express.Router();

// Initialize sample comments
CommentService.initializeSampleComments();

// GET /api/comments/dao/:daoId - Get all comments for a DAO
router.get("/dao/:daoId", authenticate, async (req, res) => {
  try {
    const { daoId } = req.params;
    const comments = await CommentService.getDaoComments(daoId);
    return res.json(comments);
  } catch (error) {
    console.error("Error getting DAO comments:", error);
    return res.status(500).json({ error: "Failed to get comments" });
  }
});

// GET /api/comments/dao/:daoId/task/:taskId - Get comments for a specific task
router.get("/dao/:daoId/task/:taskId", authenticate, async (req, res) => {
  try {
    const { daoId, taskId } = req.params;
    const comments = await CommentService.getTaskComments(
      daoId,
      parseInt(taskId),
    );
    return res.json(comments);
  } catch (error) {
    console.error("Error getting task comments:", error);
    return res.status(500).json({ error: "Failed to get task comments" });
  }
});

// POST /api/comments - Add a new comment
router.post("/", authenticate, async (req, res) => {
  try {
    const idempKey = (req.header("x-idempotency-key") || "").trim();
    if (idempKey) {
      const cached = getIdempotency(idempKey);
      if (cached) return res.status(201).json(cached);
    }

    const { daoId, taskId, content } = req.body;

    if (!daoId || taskId === undefined || !content?.trim()) {
      return res
        .status(400)
        .json({ error: "DAO ID, task ID, and content are required" });
    }

    const commentData = {
      daoId,
      taskId: parseInt(taskId),
      userId: req.user!.id,
      userName: req.user!.name,
      content: content.trim(),
    };

    const newComment = await CommentService.addComment(commentData);

    if (idempKey) setIdempotency(idempKey, newComment);

    // Broadcast to all users and send emails
    try {
      const { NotificationService } = await import(
        "../services/notificationService"
      );
      const { AuthService } = await import("../services/authService");
      const { EmailService } = await import("../services/emailService");

      NotificationService.broadcast(
        "comment_added",
        "Nouveau commentaire",
        `${newComment.userName} a commenté la tâche #${newComment.taskId}`,
        { daoId: newComment.daoId, taskId: newComment.taskId },
      );

      const users = await AuthService.getAllUsers();
      await EmailService.sendBulkNotification(
        users.map((u) => u.email),
        "Nouveau commentaire",
        `${newComment.userName} a commenté une tâche (DAO ${newComment.daoId}).`,
      );
    } catch (_) {}

    return res.status(201).json(newComment);
  } catch (error) {
    console.error("Error adding comment:", error);
    return res.status(500).json({ error: "Failed to add comment" });
  }
});

// PUT /api/comments/:id - Update a comment (only by author)
router.put("/:id", authenticate, async (req, res) => {
  try {
    const { id } = req.params;
    const { content } = req.body;

    if (!content?.trim()) {
      return res.status(400).json({ error: "Content is required" });
    }

    const updatedComment = await CommentService.updateComment(
      id,
      req.user!.id,
      content.trim(),
    );

    if (!updatedComment) {
      return res.status(404).json({ error: "Comment not found" });
    }

    // Broadcast and email
    try {
      const { NotificationService } = await import(
        "../services/notificationService"
      );
      const { AuthService } = await import("../services/authService");
      const { EmailService } = await import("../services/emailService");

      NotificationService.broadcast(
        "comment_updated",
        "Commentaire modifié",
        `${updatedComment.userName} a modifié un commentaire sur la tâche #${updatedComment.taskId}`,
        {
          daoId: updatedComment.daoId,
          taskId: updatedComment.taskId,
          commentId: updatedComment.id,
        },
      );

      const users = await AuthService.getAllUsers();
      await EmailService.sendBulkNotification(
        users.map((u) => u.email),
        "Commentaire modifié",
        `${updatedComment.userName} a modifié un commentaire (DAO ${updatedComment.daoId}).`,
      );
    } catch (_) {}

    return res.json(updatedComment);
  } catch (error) {
    console.error("Error updating comment:", error);
    if ((error as Error).message.toLowerCase().includes("unauthorized")) {
      return res.status(403).json({ error: (error as Error).message });
    }
    return res.status(500).json({ error: "Failed to update comment" });
  }
});

// DELETE /api/comments/:id - Delete a comment (author or admin)
router.delete("/:id", authenticate, async (req, res) => {
  try {
    const { id } = req.params;

    // Fetch comment before deletion for context
    const comment = await CommentService.getCommentById(id);

    const isAdmin = req.user?.role === "admin";
    const deleted = await CommentService.deleteComment(
      id,
      req.user!.id,
      Boolean(isAdmin),
    );

    if (!deleted) {
      return res.status(404).json({ error: "Comment not found" });
    }

    // Broadcast and email
    if (comment) {
      try {
        const { NotificationService } = await import(
          "../services/notificationService"
        );
        const { AuthService } = await import("../services/authService");
        const { EmailService } = await import("../services/emailService");

        NotificationService.broadcast(
          "comment_deleted",
          "Commentaire supprimé",
          `${req.user!.name} a supprimé un commentaire de ${comment.userName} sur la tâche #${comment.taskId}`,
          {
            daoId: comment.daoId,
            taskId: comment.taskId,
            commentId: comment.id,
          },
        );

        const users = await AuthService.getAllUsers();
        await EmailService.sendBulkNotification(
          users.map((u) => u.email),
          "Commentaire supprimé",
          `${req.user!.name} a supprimé un commentaire (DAO ${comment.daoId}).`,
        );
      } catch (_) {}
    }

    return res.json({ message: "Comment deleted successfully" });
  } catch (error) {
    console.error("Error deleting comment:", error);
    if ((error as Error).message.toLowerCase().includes("unauthorized")) {
      return res.status(403).json({ error: (error as Error).message });
    }
    return res.status(500).json({ error: "Failed to delete comment" });
  }
});

// GET /api/comments/recent - Get recent comments across all DAOs
router.get("/recent", authenticate, async (req, res) => {
  try {
    const limit = parseInt(req.query.limit as string) || 10;
    const comments = await CommentService.getRecentComments(limit);
    return res.json(comments);
  } catch (error) {
    console.error("Error getting recent comments:", error);
    return res.status(500).json({ error: "Failed to get recent comments" });
  }
});

export default router;
