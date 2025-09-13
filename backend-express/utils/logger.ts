// Système de logging amélioré pour remplacer console.log
export enum LogLevel {
  ERROR = 0,
  WARN = 1,
  INFO = 2,
  DEBUG = 3,
}

interface LogEntry {
  timestamp: string;
  level: LogLevel;
  message: string;
  context?: string;
  data?: any;
  userId?: string;
  ip?: string;
}

class Logger {
  private logLevel: LogLevel;
  private isDevelopment: boolean;

  constructor() {
    this.isDevelopment = process.env.NODE_ENV === "development";
    this.logLevel = this.isDevelopment ? LogLevel.DEBUG : LogLevel.INFO;
  }

  private createLogEntry(
    level: LogLevel,
    message: string,
    context?: string,
    data?: any,
    userId?: string,
    ip?: string,
  ): LogEntry {
    return {
      timestamp: new Date().toISOString(),
      level,
      message,
      context,
      data,
      userId,
      ip,
    };
  }

  private formatLogEntry(entry: LogEntry): string {
    const levelNames = ["ERROR", "WARN", "INFO", "DEBUG"];
    const levelColors = ["\x1b[31m", "\x1b[33m", "\x1b[36m", "\x1b[37m"]; // Rouge, Jaune, Cyan, Blanc

    const levelName = levelNames[entry.level];
    const levelColor = this.isDevelopment ? levelColors[entry.level] : "";
    const resetColor = this.isDevelopment ? "\x1b[0m" : "";

    let logString = `${levelColor}[${levelName}]${resetColor} ${entry.timestamp}`;

    if (entry.context) {
      logString += ` [${entry.context}]`;
    }

    logString += ` ${entry.message}`;

    if (entry.userId) {
      logString += ` (User: ${entry.userId})`;
    }

    if (entry.ip) {
      logString += ` (IP: ${entry.ip})`;
    }

    return logString;
  }

  private log(entry: LogEntry): void {
    if (entry.level <= this.logLevel) {
      const formattedLog = this.formatLogEntry(entry);

      switch (entry.level) {
        case LogLevel.ERROR:
          console.error(formattedLog);
          if (entry.data) console.error("Data:", entry.data);
          break;
        case LogLevel.WARN:
          console.warn(formattedLog);
          if (entry.data) console.warn("Data:", entry.data);
          break;
        case LogLevel.INFO:
          console.info(formattedLog);
          if (entry.data) console.info("Data:", entry.data);
          break;
        case LogLevel.DEBUG:
          if (this.isDevelopment) {
            console.log(formattedLog);
            if (entry.data) console.log("Data:", entry.data);
          }
          break;
      }
    }
  }

  error(
    message: string,
    context?: string,
    data?: any,
    userId?: string,
    ip?: string,
  ): void {
    this.log(
      this.createLogEntry(LogLevel.ERROR, message, context, data, userId, ip),
    );
  }

  warn(
    message: string,
    context?: string,
    data?: any,
    userId?: string,
    ip?: string,
  ): void {
    this.log(
      this.createLogEntry(LogLevel.WARN, message, context, data, userId, ip),
    );
  }

  info(
    message: string,
    context?: string,
    data?: any,
    userId?: string,
    ip?: string,
  ): void {
    this.log(
      this.createLogEntry(LogLevel.INFO, message, context, data, userId, ip),
    );
  }

  debug(
    message: string,
    context?: string,
    data?: any,
    userId?: string,
    ip?: string,
  ): void {
    this.log(
      this.createLogEntry(LogLevel.DEBUG, message, context, data, userId, ip),
    );
  }

  // Méthodes spécialisées pour les contextes communs
  auth(message: string, userId?: string, ip?: string, data?: any): void {
    this.info(message, "AUTH", data, userId, ip);
  }

  api(message: string, userId?: string, ip?: string, data?: any): void {
    this.info(message, "API", data, userId, ip);
  }

  security(message: string, userId?: string, ip?: string, data?: any): void {
    this.warn(message, "SECURITY", data, userId, ip);
  }

  audit(message: string, userId?: string, ip?: string, data?: any): void {
    this.info(message, "AUDIT", data, userId, ip);
  }

  // Configuration du niveau de log
  setLogLevel(level: LogLevel): void {
    this.logLevel = level;
  }

  getLogLevel(): LogLevel {
    return this.logLevel;
  }
}

// Instance singleton du logger
export const logger = new Logger();

// Middleware Express pour le logging automatique
export function requestLogger() {
  return (req: any, res: any, next: any) => {
    const start = Date.now();

    res.on("finish", () => {
      const duration = Date.now() - start;
      const message = `${req.method} ${req.originalUrl} - ${res.statusCode} - ${duration}ms`;

      if (res.statusCode >= 500) {
        logger.error(message, "HTTP", undefined, req.user?.id, req.ip);
      } else if (res.statusCode >= 400) {
        logger.warn(message, "HTTP", undefined, req.user?.id, req.ip);
      } else {
        logger.info(message, "HTTP", undefined, req.user?.id, req.ip);
      }

      if (res.statusCode >= 400) {
        logger.security(
          `Failed request: ${req.method} ${req.originalUrl}`,
          req.user?.id,
          req.ip,
          { statusCode: res.statusCode, userAgent: req.get("User-Agent") },
        );
      }
    });

    next();
  };
}
