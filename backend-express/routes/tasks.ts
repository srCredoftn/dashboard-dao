import express from "express";
import { z } from "zod";
import { authenticate, requireAdmin, auditLog } from "../middleware/auth";
import { getIdempotency, setIdempotency } from "../utils/idempotency";
import type { DaoTask } from "@shared/dao";
import { DaoService } from "../services/daoService";

const router = express.Router();

// Validation schemas
const createTaskSchema = z.object({
  name: z.string().min(1).max(200).trim(),
  isApplicable: z.boolean(),
  progress: z.number().min(0).max(100).nullable(),
  comment: z.string().max(1000).optional(),
  assignedTo: z.array(z.string().max(50)).optional(),
});

const updateTaskNameSchema = z.object({
  name: z.string().min(1).max(200).trim(),
});

// Helper to sanitize string
function sanitizeString(input: string): string {
  return input.replace(/<[^>]*>/g, "").trim();
}

// POST /api/dao/:daoId/tasks - Add new task (admin or DAO leader)
router.post(
  "/:daoId/tasks",
  authenticate,
  requireAdmin,
  auditLog("ADD_TASK"),
  async (req, res) => {
    try {
      const idempKey = (req.header("x-idempotency-key") || "").trim();
      if (idempKey) {
        const cached = getIdempotency(idempKey);
        if (cached) return res.status(201).json(cached);
      }

      const { daoId } = req.params;

      if (!daoId || daoId.length > 100) {
        return void res.status(400).json({
          error: "Invalid DAO ID",
          code: "INVALID_DAO_ID",
        });
      }

      const validatedData = createTaskSchema.parse(req.body);
      const dao = await DaoService.getDaoById(daoId);

      if (!dao) {
        return void res.status(404).json({
          error: "DAO not found",
          code: "DAO_NOT_FOUND",
        });
      }

      const existingIds = dao.tasks.map((t) => t.id);
      const newId = existingIds.length > 0 ? Math.max(...existingIds) + 1 : 1;

      const newTask: DaoTask = {
        id: newId,
        name: sanitizeString(validatedData.name),
        progress: validatedData.isApplicable ? validatedData.progress : null,
        comment: validatedData.comment
          ? sanitizeString(validatedData.comment)
          : undefined,
        isApplicable: validatedData.isApplicable,
        assignedTo: validatedData.assignedTo || [],
        lastUpdatedBy: req.user!.id,
        lastUpdatedAt: new Date().toISOString(),
      } as DaoTask;

      const updated = await DaoService.updateDao(daoId, {
        tasks: [...dao.tasks, newTask],
      });

      if (idempKey) setIdempotency(idempKey, updated);

      console.log(
        `✨ Added new task "${newTask.name}" to DAO ${daoId} by ${req.user?.email}`,
      );

      // Notifications & emails
      try {
        const { NotificationService } = await import(
          "../services/notificationService"
        );
        const { AuthService } = await import("../services/authService");
        const { EmailService } = await import("../services/emailService");
        NotificationService.broadcast(
          "task_created",
          "Nouvelle tâche créée",
          `"${newTask.name}" a été ajoutée au DAO ${daoId}`,
          { daoId, taskId: newTask.id },
        );
        const users = await AuthService.getAllUsers();
        await EmailService.sendBulkNotification(
          users.map((u) => u.email),
          "Nouvelle tâche",
          `Une nouvelle tâche "${newTask.name}" a été ajoutée au DAO ${daoId}.`,
        );
      } catch (_) {}

      return void res.status(201).json(updated);
    } catch (error) {
      if (error instanceof z.ZodError) {
        return void res.status(400).json({
          error: "Validation error",
          details: error.errors.map((e) => ({
            field: e.path.join("."),
            message: e.message,
          })),
          code: "VALIDATION_ERROR",
        });
      }

      console.error("Error in POST /api/dao/:daoId/tasks:", error);
      return void res.status(500).json({
        error: "Failed to add task",
        code: "ADD_TASK_ERROR",
      });
    }
  },
);

// PUT /api/dao/:daoId/tasks/:taskId/name - Update task name (admin or DAO leader)
router.put(
  "/:daoId/tasks/:taskId/name",
  authenticate,
  requireAdmin,
  auditLog("UPDATE_TASK_NAME"),
  async (req, res) => {
    try {
      const { daoId, taskId } = req.params;

      if (!daoId || daoId.length > 100) {
        return void res.status(400).json({
          error: "Invalid DAO ID",
          code: "INVALID_DAO_ID",
        });
      }

      const parsedTaskId = parseInt(taskId);
      if (isNaN(parsedTaskId) || parsedTaskId < 1) {
        return void res.status(400).json({
          error: "Invalid task ID",
          code: "INVALID_TASK_ID",
        });
      }

      const validatedData = updateTaskNameSchema.parse(req.body);
      const dao = await DaoService.getDaoById(daoId);

      if (!dao) {
        return void res.status(404).json({
          error: "DAO not found",
          code: "DAO_NOT_FOUND",
        });
      }

      const task = dao.tasks.find((t) => t.id === parsedTaskId);
      if (!task) {
        return void res.status(404).json({
          error: "Task not found",
          code: "TASK_NOT_FOUND",
        });
      }

      const oldName = task.name;
      task.name = sanitizeString(validatedData.name);
      task.lastUpdatedBy = req.user!.id;
      task.lastUpdatedAt = new Date().toISOString();

      const updated = await DaoService.updateDao(daoId, { tasks: dao.tasks });

      // Notifications & emails
      try {
        const { NotificationService } = await import(
          "../services/notificationService"
        );
        const { AuthService } = await import("../services/authService");
        const { EmailService } = await import("../services/emailService");
        NotificationService.broadcast(
          "task_updated",
          "Nom de tâche modifié",
          `Tâche #${parsedTaskId}: "${oldName}" → "${task.name}" (DAO ${daoId})`,
          { daoId, taskId: parsedTaskId },
        );
        const users = await AuthService.getAllUsers();
        await EmailService.sendBulkNotification(
          users.map((u) => u.email),
          "Nom de tâche modifié",
          `La tâche #${parsedTaskId} du DAO ${daoId} a été renommée: "${oldName}" → "${task.name}".`,
        );
      } catch (_) {}

      console.log(
        `📝 Updated task name from "${oldName}" to "${task.name}" in DAO ${daoId} by ${req.user?.email}`,
      );
      return res.json(updated);
    } catch (error) {
      if (error instanceof z.ZodError) {
        return void res.status(400).json({
          error: "Validation error",
          details: error.errors.map((e) => ({
            field: e.path.join("."),
            message: e.message,
          })),
          code: "VALIDATION_ERROR",
        });
      }

      console.error("Error in PUT /api/dao/:daoId/tasks/:taskId/name:", error);
      return void res.status(500).json({
        error: "Failed to update task name",
        code: "UPDATE_TASK_NAME_ERROR",
      });
    }
  },
);

// DELETE /api/dao/:daoId/tasks/:taskId - Delete task (disabled)
router.delete(
  "/:daoId/tasks/:taskId",
  authenticate,
  auditLog("DELETE_TASK_ATTEMPT"),
  async (_req, res) => {
    return res.status(403).json({
      error: "Task deletion is disabled",
      code: "TASK_DELETE_DISABLED",
    });
  },
);

export default router;
