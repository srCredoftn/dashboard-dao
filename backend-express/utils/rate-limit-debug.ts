// Utilitaire pour diagnostiquer et déboguer les problèmes de rate limiting

import type { Request, Response } from "express";

// Interface pour tracker les rate limits
interface RateLimitInfo {
  ip: string;
  userId?: string;
  endpoint: string;
  attempts: number;
  resetTime: Date;
  remaining: number;
}

// Store global pour traquer les rate limits en développement
const rateLimitTracker = new Map<string, RateLimitInfo>();

export class RateLimitDebugger {
  // Middleware pour tracker les rate limits
  static trackRateLimit() {
    return (req: Request, res: Response, next: Function) => {
      if (process.env.NODE_ENV === "development") {
        const key = `${String(req.ip)}:${req.originalUrl}`;
        const rateLimitHeaders = {
          limit: res.get("X-RateLimit-Limit"),
          remaining: res.get("X-RateLimit-Remaining"),
          reset: res.get("X-RateLimit-Reset"),
        };

        if (rateLimitHeaders.limit) {
          rateLimitTracker.set(key, {
            ip: String(req.ip),
            userId: (req as any).user?.id,
            endpoint: req.originalUrl,
            attempts:
              parseInt(rateLimitHeaders.limit) -
              parseInt(rateLimitHeaders.remaining || "0"),
            resetTime: new Date(parseInt(rateLimitHeaders.reset || "0") * 1000),
            remaining: parseInt(rateLimitHeaders.remaining || "0"),
          });
        }
      }
      next();
    };
  }

  // Obtenir les informations de rate limiting pour une IP
  static getRateLimitInfo(ip: string): RateLimitInfo[] {
    return Array.from(rateLimitTracker.values()).filter(
      (info) => info.ip === ip,
    );
  }

  // Obtenir toutes les informations de rate limiting
  static getAllRateLimitInfo(): RateLimitInfo[] {
    return Array.from(rateLimitTracker.values());
  }

  // Vérifier si une IP est proche de la limite
  static isNearLimit(ip: string, threshold: number = 0.8): boolean {
    const infos = this.getRateLimitInfo(ip);
    return infos.some(
      (info) => info.remaining / (info.attempts + info.remaining) < threshold,
    );
  }

  // Logger pour diagnostiquer les problèmes de rate limiting
  static logRateLimitStatus(req: Request, res: Response) {
    if (process.env.NODE_ENV === "development" && res.statusCode === 429) {
      console.log("\n🚨 RATE LIMIT HIT:");
      console.log(`  IP: ${req.ip}`);
      console.log(`  User: ${(req as any).user?.email || "anonymous"}`);
      console.log(`  Endpoint: ${req.method} ${req.originalUrl}`);
      console.log(`  Time: ${new Date().toISOString()}`);

      const rateLimitHeaders = {
        limit: res.get("X-RateLimit-Limit"),
        remaining: res.get("X-RateLimit-Remaining"),
        reset: res.get("X-RateLimit-Reset"),
        retryAfter: res.get("Retry-After"),
      };

      console.log("  Headers:", rateLimitHeaders);

      if (rateLimitHeaders.reset) {
        const resetTime = new Date(parseInt(rateLimitHeaders.reset) * 1000);
        console.log(`  Reset Time: ${resetTime.toISOString()}`);
        console.log(
          `  Time Until Reset: ${Math.ceil((resetTime.getTime() - Date.now()) / 1000)}s`,
        );
      }

      console.log("\n💡 Solutions:");
      console.log("  1. Wait for the rate limit to reset");
      console.log("  2. Use different IP/user for testing");
      console.log("  3. Adjust rate limit config in development");
      console.log("  4. Clear rate limit cache (if implemented)\n");
    }
  }

  // Middleware pour logger automatiquement les rate limits
  static autoLog() {
    return (req: Request, res: Response, next: Function) => {
      const originalSend = res.send;

      res.send = function (body) {
        RateLimitDebugger.logRateLimitStatus(req, res);
        return originalSend.call(this, body);
      };

      next();
    };
  }

  // Nettoyer les anciens enregistrements
  static cleanup() {
    const now = Date.now();
    for (const [key, info] of rateLimitTracker.entries()) {
      if (info.resetTime.getTime() < now) {
        rateLimitTracker.delete(key);
      }
    }
  }

  // Route de débogage pour voir l'état du rate limiting
  static getDebugRoute() {
    return (req: Request, res: Response) => {
      if (process.env.NODE_ENV !== "development") {
        res
          .status(404)
          .json({ error: "Debug routes only available in development" });
        return;
      }

      // Nettoyer les anciens enregistrements
      this.cleanup();

      const allInfo = this.getAllRateLimitInfo();
      const userIP = String(req.ip);
      const userInfo = this.getRateLimitInfo(userIP);

      res.json({
        currentIP: userIP,
        isNearLimit: this.isNearLimit(userIP),
        userRateLimits: userInfo,
        allRateLimits: allInfo,
        timestamp: new Date().toISOString(),
        tips: [
          "Rate limits reset automatically after the time window",
          "In development, limits are more permissive",
          "Check X-RateLimit-* headers for detailed info",
        ],
      });
    };
  }

  // Utilitaire pour créer une exception temporaire
  static createBypass(ip: string, durationMs: number = 60000) {
    if (process.env.NODE_ENV === "development") {
      console.log(
        `🔓 Creating rate limit bypass for IP ${ip} for ${durationMs}ms`,
      );
      // Cette fonction pourrait être étendue pour intégrer avec le système de rate limiting
      return true;
    }
    return false;
  }
}

// Nettoyer périodiquement les anciens enregistrements
if (process.env.NODE_ENV === "development") {
  setInterval(() => {
    RateLimitDebugger.cleanup();
  }, 60000); // Toutes les minutes
}
