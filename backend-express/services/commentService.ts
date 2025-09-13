import type { TaskComment } from "@shared/dao";

// In-memory comment storage
let comments: TaskComment[] = [];

export class CommentService {
  // Get all comments for a specific task
  static async getTaskComments(
    daoId: string,
    taskId: number,
  ): Promise<TaskComment[]> {
    return comments
      .filter((comment) => comment.daoId === daoId && comment.taskId === taskId)
      .sort(
        (a, b) =>
          new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime(),
      );
  }

  // Get all comments for a DAO
  static async getDaoComments(daoId: string): Promise<TaskComment[]> {
    return comments
      .filter((comment) => comment.daoId === daoId)
      .sort(
        (a, b) =>
          new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime(),
      );
  }

  // Add a new comment
  static async addComment(
    commentData: Omit<TaskComment, "id" | "createdAt">,
  ): Promise<TaskComment> {
    const comment: TaskComment = {
      ...commentData,
      id: `comment_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      createdAt: new Date().toISOString(),
    };

    comments.push(comment);

    console.log("💬 New comment added:", {
      daoId: comment.daoId,
      taskId: comment.taskId,
      userName: comment.userName,
      content: comment.content.substring(0, 50) + "...",
    });

    return comment;
  }

  // Update a comment (only by the author)
  static async updateComment(
    commentId: string,
    userId: string,
    newContent: string,
  ): Promise<TaskComment | null> {
    const comment = comments.find((c) => c.id === commentId);

    if (!comment) {
      return null;
    }

    // Only the author can update their comment
    if (comment.userId !== userId) {
      throw new Error("Unauthorized: Can only update your own comments");
    }

    comment.content = newContent;

    console.log("✏️ Comment updated:", commentId);
    return comment;
  }

  // Delete a comment (author or admin)
  static async deleteComment(
    commentId: string,
    userId: string,
    isAdmin = false,
  ): Promise<boolean> {
    const commentIndex = comments.findIndex((c) => c.id === commentId);

    if (commentIndex === -1) {
      return false;
    }

    const comment = comments[commentIndex];

    // Allow if author or admin
    if (!isAdmin && comment.userId !== userId) {
      throw new Error("Unauthorized: Can only delete your own comments");
    }

    comments.splice(commentIndex, 1);

    console.log("🗑️ Comment deleted:", commentId);
    return true;
  }

  // Get recent comments across all DAOs (for activity feed)
  static async getRecentComments(limit: number = 10): Promise<TaskComment[]> {
    return comments
      .sort(
        (a, b) =>
          new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime(),
      )
      .slice(0, limit);
  }

  // Get comment by ID
  static async getCommentById(commentId: string): Promise<TaskComment | null> {
    return comments.find((c) => c.id === commentId) || null;
  }

  // Initialize with some sample comments
  static initializeSampleComments() {
    if (comments.length === 0) {
      const sampleComments: TaskComment[] = [
        {
          id: "comment_1",
          taskId: 1,
          daoId: "1",
          userId: "2",
          userName: "Marie Dubois",
          content:
            "Drive créé et documents de base ajoutés. Prêt pour la phase suivante.",
          createdAt: new Date(Date.now() - 2 * 60 * 60 * 1000).toISOString(), // 2 hours ago
        },
        {
          id: "comment_2",
          taskId: 2,
          daoId: "1",
          userId: "3",
          userName: "Pierre Martin",
          content:
            "Demande de caution en cours. Attente de la réponse de la banque.",
          createdAt: new Date(Date.now() - 1 * 60 * 60 * 1000).toISOString(), // 1 hour ago
        },
        {
          id: "comment_3",
          taskId: 2,
          daoId: "1",
          userId: "2",
          userName: "Marie Dubois",
          content: "Mise à jour: La banque a confirmé. Dossier complet à 75%.",
          createdAt: new Date(Date.now() - 30 * 60 * 1000).toISOString(), // 30 minutes ago
        },
      ];

      comments.push(...sampleComments);
      console.log("📝 Sample comments initialized");
    }
  }
}
