/**
 * Smart Approve — structured logger.
 *
 * Writes timestamped lines to a dedicated log file
 * (~/.omp/logs/smart-approve.log) so diagnosis does not depend on whether
 * the host captures extension stderr.  Also mirrors to console.error for
 * hosts that do capture it.  All other modules route diagnostics through
 * this single sink.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import * as os from "node:os";

export class Logger {
  private readonly logPath: string;
  private initialized = false;

  constructor(logDir?: string) {
    const dir = logDir ?? this.defaultLogDir();
    this.logPath = path.join(dir, "smart-approve.log");
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

  /** Ensure the log file exists; called once on first write. */
  private ensure(): void {
    if (this.initialized) return;
    try {
      const dir = path.dirname(this.logPath);
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
      this.initialized = true;
    } catch {
      // best-effort; logging must never throw
    }
  }

  /** Write a line.  Never throws — diagnostics are best-effort. */
  log(message: string): void {
    const line = `${new Date().toISOString()} ${message}`;
    this.ensure();
    try {
      fs.appendFileSync(this.logPath, line + "\n", "utf-8");
    } catch {
      // ignore
    }
    // Mirror to stderr for hosts that capture it.
    console.error(`[smart-approve] ${message}`);
  }
}
