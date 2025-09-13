import { devLog } from "@/utils/devLogger";

export interface ServerNotification {
  id: string;
  type:
    | "role_update"
    | "comment_added"
    | "comment_updated"
    | "comment_deleted"
    | "task_created"
    | "task_deleted"
    | "task_updated"
    | "task_assigned"
    | "task_unassigned"
    | "system";
  title: string;
  message: string;
  data?: any;
  createdAt: string;
  read: boolean;
}

import { authService } from "./authService";
import secureFetch from "@/utils/secure-fetch";

async function api<T>(input: RequestInfo, init?: RequestInit): Promise<T> {
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(init?.headers as Record<string, string> | undefined),
  };
  const token = authService.getToken();
  if (token) headers.Authorization = `Bearer ${token}`;

  try {
    // Use secureFetch to bypass third-party fetch interceptors (FullStory, Sentry, ...)
    const response = await secureFetch.fetch(
      typeof input === "string" ? input : input.toString(),
      {
        ...init,
        headers,
        credentials: "include",
        useNativeFetch: true,
        maxRetries: 2,
        timeout: 8000,
      } as any,
    );

    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    return await response.json();
  } catch (err) {
    // Reformat network errors to be less noisy and consistent
    const message = err instanceof Error ? err.message : String(err);
    if (
      message.includes("Failed to fetch") ||
      message.includes("Network request failed")
    ) {
      throw new Error("Network unreachable: failed to contact backend");
    }
    throw err;
  }
}

export const notificationsApi = {
  async list(): Promise<ServerNotification[]> {
    try {
      return await api<ServerNotification[]>("/api/notifications");
    } catch (e) {
      // Network errors are expected in remote previews where backend is not reachable.
      // Log as warning (not error) to avoid alarming messages in the console.
      devLog.warn(
        "Failed to fetch notifications (network/preview):",
        (e as Error).message,
      );
      return [];
    }
  },
  async markRead(id: string): Promise<void> {
    try {
      await api(`/api/notifications/${id}/read`, { method: "PUT" });
    } catch (e) {
      devLog.error("Failed to mark notification as read", e);
    }
  },
  async markAllRead(): Promise<void> {
    try {
      await api(`/api/notifications/read-all`, { method: "PUT" });
    } catch (e) {
      devLog.error("Failed to mark all notifications as read", e);
    }
  },
};
