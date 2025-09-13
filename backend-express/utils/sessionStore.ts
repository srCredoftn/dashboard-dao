import { writeFileSync, readFileSync, existsSync } from "fs";
import { join } from "path";
import type { AuthUser } from "@shared/dao";

const SESSION_FILE = join(process.cwd(), ".sessions.json");

export class SessionStore {
  private static sessions = new Map<string, AuthUser>();
  private static loaded = false;

  // Load sessions from file
  static loadSessions(): void {
    if (this.loaded) return;

    try {
      if (existsSync(SESSION_FILE)) {
        const data = readFileSync(SESSION_FILE, "utf8");
        const sessionsArray = JSON.parse(data);
        this.sessions = new Map(sessionsArray);
        console.log("📁 Loaded", this.sessions.size, "sessions from storage");
      }
    } catch (error) {
      console.warn("⚠️ Failed to load sessions:", error);
      this.sessions = new Map();
    }
    this.loaded = true;
  }

  // Save sessions to file
  static saveSessions(): void {
    try {
      const sessionsArray = Array.from(this.sessions.entries());
      writeFileSync(SESSION_FILE, JSON.stringify(sessionsArray, null, 2));
    } catch (error) {
      console.warn("⚠️ Failed to save sessions:", error);
    }
  }

  // Get session
  static getSession(token: string): AuthUser | null {
    this.loadSessions();
    return this.sessions.get(token) || null;
  }

  // Set session
  static setSession(token: string, user: AuthUser): void {
    this.loadSessions();
    this.sessions.set(token, user);
    this.saveSessions();
  }

  // Delete session
  static deleteSession(token: string): boolean {
    this.loadSessions();
    const deleted = this.sessions.delete(token);
    if (deleted) {
      this.saveSessions();
    }
    return deleted;
  }

  // Delete sessions for user
  static deleteUserSessions(userId: string): void {
    this.loadSessions();
    let changed = false;
    for (const [token, user] of this.sessions.entries()) {
      if (user.id === userId) {
        this.sessions.delete(token);
        changed = true;
      }
    }
    if (changed) {
      this.saveSessions();
    }
  }

  // Get all sessions
  static getAllSessions(): Map<string, AuthUser> {
    this.loadSessions();
    return new Map(this.sessions);
  }
}
