export type NotificationType =
  | "role_update"
  | "comment_added"
  | "comment_updated"
  | "comment_deleted"
  | "task_created"
  | "task_deleted"
  | "task_updated"
  | "task_assigned"
  | "task_unassigned"
  | "task_reordered"
  | "dao_created"
  | "dao_updated"
  | "dao_deleted"
  | "user_created"
  | "system";

export interface ServerNotification {
  id: string;
  type: NotificationType;
  title: string;
  message: string;
  data?: Record<string, any>;
  recipients: "all" | string[]; // "all" means all active users
  readBy: Set<string>; // userIds who read it
  createdAt: string;
}

class NotificationServiceClass {
  private notifications: ServerNotification[] = [];

  listForUser(
    userId: string,
  ): (Omit<ServerNotification, "readBy" | "recipients"> & { read: boolean })[] {
    return this.notifications
      .filter(
        (n) =>
          n.recipients === "all" ||
          (Array.isArray(n.recipients) && n.recipients.includes(userId)),
      )
      .sort(
        (a, b) =>
          new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime(),
      )
      .map((n) => ({
        id: n.id,
        type: n.type,
        title: n.title,
        message: n.message,
        data: n.data,
        createdAt: n.createdAt,
        read: n.readBy.has(userId),
      }));
  }

  add(
    notification: Omit<ServerNotification, "id" | "readBy" | "createdAt">,
  ): ServerNotification {
    const newNotif: ServerNotification = {
      ...notification,
      id: `srv_notif_${Date.now()}_${Math.random().toString(36).slice(2, 9)}`,
      readBy: new Set(),
      createdAt: new Date().toISOString(),
    };
    this.notifications.unshift(newNotif);
    // Limit total notifications to 500
    if (this.notifications.length > 500) this.notifications.pop();
    return newNotif;
  }

  broadcast(
    type: NotificationType,
    title: string,
    message: string,
    data?: Record<string, any>,
  ): ServerNotification {
    return this.add({ type, title, message, data, recipients: "all" });
  }

  markRead(userId: string, notifId: string): boolean {
    const notif = this.notifications.find((n) => n.id === notifId);
    if (!notif) return false;
    notif.readBy.add(userId);
    return true;
  }

  markAllRead(userId: string): number {
    let count = 0;
    for (const n of this.notifications) {
      if (
        n.recipients === "all" ||
        (Array.isArray(n.recipients) && n.recipients.includes(userId))
      ) {
        if (!n.readBy.has(userId)) {
          n.readBy.add(userId);
          count++;
        }
      }
    }
    return count;
  }

  // Clear all notifications (server-side)
  clearAll(): void {
    this.notifications = [];
  }
}

export const NotificationService = new NotificationServiceClass();
