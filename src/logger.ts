/**
 * Smart Approve — structured logger with rotation.
 *
 * Writes timestamped lines to a dedicated log file
 * (~/.omp/logs/smart-approve.log) so diagnosis does not depend on whether
 * the host captures extension stderr.  All other modules route diagnostics
 * through this single sink.
 *
 * Log files are rotated when they exceed 5 MB (up to 3 historical files)
 * and stale files older than 30 days are cleaned on startup.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";
import { RotatingLog } from "./utils/rotating-log.js";

export class Logger {
  private readonly rotatingLog: RotatingLog;

  constructor(logDir?: string) {
    const dir = logDir ?? this.defaultLogDir();
    const logPath = path.join(dir, "smart-approve.log");

    // Ensure directory exists before RotatingLog tries to write.
    try {
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    } catch {}

    this.rotatingLog = new RotatingLog({
      filePath: logPath,
      maxBytes: 5 * 1024 * 1024,  // 5 MB
      maxFiles: 3,
      maxAgeMs: 30 * 24 * 60 * 60 * 1000,  // 30 days
    });
    this.rotatingLog.cleanStale();
  }

  private defaultLogDir(): string {
    const home = os.homedir();
    const ompLogs = path.join(home, ".omp", "logs");
    const piLogs = path.join(home, ".pi", "logs");
    if (fs.existsSync(ompLogs)) return ompLogs;
    if (fs.existsSync(piLogs)) return piLogs;
    // Fall back to .omp/agent (config dir) if logs dir doesn't exist yet
    const ompAgent = path.join(home, ".omp", "agent");
    return ompAgent;
  }

  /** Write a line.  Never throws — diagnostics are best-effort. */
  log(message: string): void {
    const line = `${new Date().toISOString()} ${message}\n`;
    this.rotatingLog.write(line);
  }
}
