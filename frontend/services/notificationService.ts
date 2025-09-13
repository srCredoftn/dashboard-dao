import type { AuthUser, Dao } from "@shared/dao";

export interface Notification {
  id: string;
  userId: string;
  type:
    | "dao_assignment"
    | "task_assignment"
    | "dao_update"
    | "task_update"
    | "mention";
  title: string;
  message: string;
  data?: any;
  read: boolean;
  createdAt: string;
}

export interface NotificationSettings {
  daoAssignments: boolean;
  taskAssignments: boolean;
  daoUpdates: boolean;
  taskUpdates: boolean;
  mentions: boolean;
}

class NotificationService {
  private notifications: Notification[] = [];
  private listeners: Array<(notifications: Notification[]) => void> = [];
  private userSettings: Record<string, NotificationSettings> = {};

  // Default notification settings
  private defaultSettings: NotificationSettings = {
    daoAssignments: true,
    taskAssignments: true,
    daoUpdates: true,
    taskUpdates: false,
    mentions: true,
  };

  constructor() {
    this.loadFromStorage();
  }

  // Load notifications and settings from localStorage
  private loadFromStorage(): void {
    try {
      const stored = localStorage.getItem("notifications");
      if (stored) {
        this.notifications = JSON.parse(stored);
      }

      const settings = localStorage.getItem("notification_settings");
      if (settings) {
        this.userSettings = JSON.parse(settings);
      }
    } catch (error) {
      console.warn("Failed to load notifications from storage:", error);
    }
  }

  // Save to localStorage
  private saveToStorage(): void {
    try {
      localStorage.setItem("notifications", JSON.stringify(this.notifications));
      localStorage.setItem(
        "notification_settings",
        JSON.stringify(this.userSettings),
      );
    } catch (error) {
      console.warn("Failed to save notifications to storage:", error);
    }
  }

  // Add listener for notification updates
  subscribe(listener: (notifications: Notification[]) => void): () => void {
    this.listeners.push(listener);

    // Return unsubscribe function
    return () => {
      const index = this.listeners.indexOf(listener);
      if (index > -1) {
        this.listeners.splice(index, 1);
      }
    };
  }

  // Notify all listeners
  private notifyListeners(): void {
    this.listeners.forEach((listener) => listener([...this.notifications]));
  }

  // Get user's notification settings
  getUserSettings(userId: string): NotificationSettings {
    return this.userSettings[userId] || this.defaultSettings;
  }

  // Update user's notification settings
  updateUserSettings(
    userId: string,
    settings: Partial<NotificationSettings>,
  ): void {
    this.userSettings[userId] = {
      ...this.getUserSettings(userId),
      ...settings,
    };
    this.saveToStorage();
  }

  // Create a new notification
  private createNotification(
    userId: string,
    type: Notification["type"],
    title: string,
    message: string,
    data?: any,
  ): void {
    const settings = this.getUserSettings(userId);

    // Check if user wants this type of notification
    const shouldNotify =
      (type === "dao_assignment" && settings.daoAssignments) ||
      (type === "task_assignment" && settings.taskAssignments) ||
      (type === "dao_update" && settings.daoUpdates) ||
      (type === "task_update" && settings.taskUpdates) ||
      (type === "mention" && settings.mentions);

    if (!shouldNotify) return;

    const notification: Notification = {
      id: `notif_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
      userId,
      type,
      title,
      message,
      data,
      read: false,
      createdAt: new Date().toISOString(),
    };

    this.notifications.unshift(notification);

    // Keep only last 100 notifications per user
    const userNotifications = this.notifications.filter(
      (n) => n.userId === userId,
    );
    if (userNotifications.length > 100) {
      const toRemove = userNotifications.slice(100);
      this.notifications = this.notifications.filter(
        (n) => !toRemove.includes(n),
      );
    }

    this.saveToStorage();
    this.notifyListeners();

    console.log(`📧 Notification created for ${userId}:`, title);
  }

  // Notify user about DAO assignment
  notifyDaoAssignment(
    user: AuthUser,
    dao: Dao,
    role: "chef_equipe" | "membre_equipe",
  ): void {
    const roleText =
      role === "chef_equipe" ? "chef d'équipe" : "membre d'équipe";
    this.createNotification(
      user.id,
      "dao_assignment",
      "Nouvelle assignation DAO",
      `Vous avez été assigné(e) comme ${roleText} sur le DAO ${dao.numeroListe} - ${dao.objetDossier}`,
      { daoId: dao.id, role },
    );
  }

  // Notify user about task assignment
  notifyTaskAssignment(user: AuthUser, dao: Dao, taskName: string): void {
    this.createNotification(
      user.id,
      "task_assignment",
      "Nouvelle tâche assignée",
      `Une nouvelle tâche "${taskName}" vous a été assignée sur le DAO ${dao.numeroListe}`,
      { daoId: dao.id, taskName },
    );
  }

  // Public method to add notifications (for mentions, etc.)
  addNotification(
    userId: string,
    type: Notification["type"],
    title: string,
    message: string,
    data?: any,
  ): void {
    this.createNotification(userId, type, title, message, data);
  }

  // Notify about DAO updates
  notifyDaoUpdate(userIds: string[], dao: Dao, updateType: string): void {
    userIds.forEach((userId) => {
      this.createNotification(
        userId,
        "dao_update",
        "Mise à jour DAO",
        `Le DAO ${dao.numeroListe} a été mis à jour: ${updateType}`,
        { daoId: dao.id, updateType },
      );
    });
  }

  // Get notifications for a user
  getUserNotifications(userId: string): Notification[] {
    return this.notifications
      .filter((n) => n.userId === userId)
      .sort(
        (a, b) =>
          new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime(),
      );
  }

  // Get unread count for a user
  getUnreadCount(userId: string): number {
    return this.notifications.filter((n) => n.userId === userId && !n.read)
      .length;
  }

  // Mark notification as read
  markAsRead(notificationId: string): void {
    const notification = this.notifications.find(
      (n) => n.id === notificationId,
    );
    if (notification) {
      notification.read = true;
      this.saveToStorage();
      this.notifyListeners();
    }
  }

  // Mark all notifications as read for a user
  markAllAsRead(userId: string): void {
    const userNotifications = this.notifications.filter(
      (n) => n.userId === userId && !n.read,
    );
    userNotifications.forEach((n) => (n.read = true));

    if (userNotifications.length > 0) {
      this.saveToStorage();
      this.notifyListeners();
    }
  }

  // Delete a notification
  deleteNotification(notificationId: string): void {
    const index = this.notifications.findIndex((n) => n.id === notificationId);
    if (index > -1) {
      this.notifications.splice(index, 1);
      this.saveToStorage();
      this.notifyListeners();
    }
  }

  // Clear all notifications for a user
  clearAllNotifications(userId: string): void {
    const userNotifications = this.notifications.filter(
      (n) => n.userId === userId,
    );
    if (userNotifications.length > 0) {
      this.notifications = this.notifications.filter(
        (n) => n.userId !== userId,
      );
      this.saveToStorage();
      this.notifyListeners();
    }
  }
}

export const notificationService = new NotificationService();
