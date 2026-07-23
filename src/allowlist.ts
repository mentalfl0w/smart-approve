/**
 * Smart Approve — decision memory (allow-list).
 *
 * Tracks session (in-memory) and permanent (disk-persisted) allow
 * decisions so a repeated dangerous command doesn't re-prompt within
 * the same session or ever (if permanent).  Encapsulates key generation,
 * dedup, and persistence so the hook stays linear.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import type { AllowEntry } from "./types";
import { normalize } from "./behaviors";
import type { Logger } from "./logger";

/** Normalize a key for dedup: tool + normalized-content + cwd. */
function makeAllowKey(tool: string, content: string, cwd: string): string {
  const normalized = tool === "bash"
    ? normalize(content)
    : path.resolve(content);
  return `${tool}::${normalized}::${cwd}`;
}

/**
 * Allow-list with session + permanent tiers.
 * Session allows live in-memory; permanent allows are JSON-persisted.
 */
export class AllowList {
  private readonly sessionAllows = new Set<string>();
  private permanent: AllowEntry[];
  private readonly allowListPath: string;

  constructor(allowListPath: string, private readonly logger?: Logger) {
    this.allowListPath = allowListPath;
    this.permanent = this.loadPermanent();
  }

  /** Load permanent allow-list from disk. */
  private loadPermanent(): AllowEntry[] {
    try {
      if (fs.existsSync(this.allowListPath)) {
        const raw = fs.readFileSync(this.allowListPath, "utf-8");
        const data = JSON.parse(raw);
        if (Array.isArray(data.permanent)) return data.permanent;
        if (Array.isArray(data)) return data; // legacy format
      }
    } catch {
      // ignore
    }
    return [];
  }

  /** Save permanent allow-list to disk. */
  private savePermanent(): void {
    try {
      const dir = path.dirname(this.allowListPath);
      if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
      fs.writeFileSync(this.allowListPath, JSON.stringify({ permanent: this.permanent }, null, 2), "utf-8");
    } catch {
      // best-effort; don't block execution
    }
  }

  /** Check if a decision is remembered (session or permanent). */
  isAllowed(tool: string, content: string, cwd: string): boolean {
    const key = makeAllowKey(tool, content, cwd);
    if (this.sessionAllows.has(key)) return true;
    return this.permanent.some(
      (e) => e.tool === tool && e.key === key.split("::")[1] && e.cwd === cwd,
    );
  }

  /** Record a session allow. */
  rememberSession(tool: string, content: string, cwd: string): void {
    this.sessionAllows.add(makeAllowKey(tool, content, cwd));
  }

  /** Record a permanent allow (persisted to disk). */
  rememberPermanent(tool: string, content: string, cwd: string): void {
    const entry: AllowEntry = {
      tool,
      key: tool === "bash" ? normalize(content) : path.resolve(content),
      cwd,
      timestamp: new Date().toISOString(),
    };
    this.permanent = this.permanent.filter(
      (e) => !(e.tool === entry.tool && e.key === entry.key && e.cwd === entry.cwd),
    );
    this.permanent.push(entry);
    this.savePermanent();
  }
}
