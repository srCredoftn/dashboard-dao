import {
  createContext,
  useContext,
  useState,
  useEffect,
  ReactNode,
} from "react";
import { useAuth } from "@/contexts/AuthContext";
import {
  notificationService,
  type Notification,
} from "@/services/notificationService";
import {
  notificationsApi,
  type ServerNotification,
} from "@/services/notificationsApi";

interface NotificationContextType {
  notifications: Notification[];
  unreadCount: number;
  markAsRead: (notificationId: string) => void;
  markAllAsRead: () => void;
  removeNotification: (notificationId: string) => void;
  clearAll: () => void;
  refresh: () => Promise<void>;
  addNotification: (notification: {
    type: Notification["type"];
    title: string;
    message: string;
    data?: any;
    taskId?: number;
    daoId?: string;
  }) => void;
}

const NotificationContext = createContext<NotificationContextType | undefined>(
  undefined,
);

export function NotificationProvider({ children }: { children: ReactNode }) {
  let auth;
  try {
    auth = useAuth();
  } catch (error) {
    console.error("NotificationProvider: Auth context not available", error);
    auth = { user: null, isLoading: false };
  }

  const { user, isLoading } = auth;
  const [notifications, setNotifications] = useState<Notification[]>([]);
  const [dismissedIds, setDismissedIds] = useState<string[]>([]);

  // Load dismissed ids for current user
  useEffect(() => {
    if (!user) return;
    const key = `dismissed_notifications_${user.id}`;
    try {
      const stored = localStorage.getItem(key);
      setDismissedIds(stored ? JSON.parse(stored) : []);
    } catch {
      setDismissedIds([]);
    }
  }, [user]);

  const refresh = async () => {
    if (!user) return;
    const serverNotifs = await notificationsApi.list();
    const local = notificationService.getUserNotifications(user.id);
    const merged: Notification[] = [
      ...serverNotifs.map<Notification>((sn: ServerNotification) => ({
        id: sn.id,
        userId: user.id,
        type:
          sn.type === "role_update"
            ? "dao_update"
            : sn.type === "task_assigned"
              ? "task_assignment"
              : "task_update",
        title: sn.title,
        message: sn.message,
        data: sn.data,
        read: sn.read,
        createdAt: sn.createdAt,
      })),
      ...local.filter((ln) => !serverNotifs.find((sn) => sn.id === ln.id)),
    ]
      .filter((n) => !dismissedIds.includes(n.id))
      .sort(
        (a, b) =>
          new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime(),
      );
    setNotifications(merged);
  };

  // Subscribe to local notification service updates and poll server
  useEffect(() => {
    if (!user) return;

    const unsubscribe = notificationService.subscribe((updated) => {
      const userNotifications = updated
        .filter((n) => n.userId === user.id)
        .filter((n) => !dismissedIds.includes(n.id));
      setNotifications(userNotifications);
    });

    refresh();
    const id = setInterval(refresh, 10000);

    return () => {
      clearInterval(id);
      unsubscribe();
    };
  }, [user, dismissedIds]);

  // Handle early returns AFTER all hooks are called
  if (!user || isLoading) {
    return <>{children}</>;
  }

  const isServerNotificationId = (id: string) => id.startsWith("srv_notif_");

  const markAsRead = (notificationId: string) => {
    notificationService.markAsRead(notificationId);
    if (isServerNotificationId(notificationId)) {
      notificationsApi.markRead(notificationId).catch(() => {});
    }
  };

  const markAllAsRead = () => {
    if (user) {
      notificationService.markAllAsRead(user.id);
      notificationsApi.markAllRead().catch(() => {});
    }
  };

  const removeNotification = (notificationId: string) => {
    if (isServerNotificationId(notificationId)) {
      notificationsApi.markRead(notificationId).catch(() => {});
    }
    notificationService.deleteNotification(notificationId);
    if (user) {
      const key = `dismissed_notifications_${user.id}`;
      const next = Array.from(new Set([...dismissedIds, notificationId]));
      setDismissedIds(next);
      try {
        localStorage.setItem(key, JSON.stringify(next));
      } catch {}
    }
  };

  const clearAll = () => {
    if (user) {
      const key = `dismissed_notifications_${user.id}`;
      const idsToDismiss = notifications.map((n) => n.id);
      const next = Array.from(new Set([...dismissedIds, ...idsToDismiss]));
      setDismissedIds(next);
      try {
        localStorage.setItem(key, JSON.stringify(next));
      } catch {}
      notificationService.clearAllNotifications(user.id);
      notificationsApi.markAllRead().catch(() => {});
      setNotifications([]);
    }
  };

  const addNotification = (notification: {
    type: Notification["type"];
    title: string;
    message: string;
    data?: any;
    taskId?: number;
    daoId?: string;
  }) => {
    if (user) {
      const data = {
        ...notification.data,
        ...(notification.taskId && { taskId: notification.taskId }),
        ...(notification.daoId && { daoId: notification.daoId }),
      };
      notificationService.addNotification(
        user.id,
        notification.type,
        notification.title,
        notification.message,
        data,
      );
    }
  };

  const unreadCount = notifications.filter((n) => !n.read).length;

  return (
    <NotificationContext.Provider
      value={{
        notifications,
        unreadCount,
        markAsRead,
        markAllAsRead,
        removeNotification,
        clearAll,
        refresh,
        addNotification,
      }}
    >
      {children}
    </NotificationContext.Provider>
  );
}

export function useNotifications() {
  const context = useContext(NotificationContext);
  if (context === undefined) {
    throw new Error(
      "useNotifications must be used within a NotificationProvider",
    );
  }
  return context;
}

// Version optionnelle qui retourne null si le contexte n'est pas disponible
export function useNotificationsOptional() {
  try {
    return useNotifications();
  } catch {
    return null;
  }
}
