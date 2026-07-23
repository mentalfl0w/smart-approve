/**
 * Smart Approve — i18n strings + locale detection.
 *
 * Bilingual (zh / en) labels for every user-facing string and the LLM
 * prompt template fields.  Locale detection is cross-platform: it reads
 * LC_ALL / LC_MESSAGES / LANG, and on macOS falls back to AppleLocale.
 */

export interface I18nLang {
  analyzing: string;
  confirmTitle: (label: string) => string;
  confirmPathTitle: (p: string) => string;
  risk: string;
  summary: string;
  detail: string;
  recommend: string;
  command: string;
  filePath: string;
  allowPrompt: string;
  analysisUnavailable: string;
  blockedNoUI: (label: string) => string;
  blockedPathNoUI: (p: string) => string;
  userDenied: (label: string) => string;
  promptIntro: string;
  promptContext: string;
  promptRule: string;
  promptCommand: string;
  promptOutput: string;
  promptSummaryDesc: string;
  promptDetailDesc: string;
  promptRecommendDesc: string;
  promptOnlyJson: string;
  sessionAllow: string;
  permanentAllow: string;
  rememberQuestion: string;
  configLoaded: (p: string) => string;
  configError: (p: string) => string;
}

export type I18n = I18nLang;
export type Lang = "zh" | "en";

const I18N: Record<Lang, I18nLang> = {
  zh: {
    analyzing: "⚡ 正在用模型分析命令风险…",
    confirmTitle: (label) => `⚠️ 高危命令确认: ${label}`,
    confirmPathTitle: (p) => `⚠️ 敏感路径保护: ${p}`,
    risk: "风险等级",
    summary: "摘要",
    detail: "详情",
    recommend: "建议",
    command: "命令",
    filePath: "文件",
    allowPrompt: "是否允许执行？",
    analysisUnavailable: "（模型分析不可用）",
    blockedNoUI: (label) => `[smart-approve] 高危命令被拦截（无 UI 无法确认）: ${label}`,
    blockedPathNoUI: (p) => `[smart-approve] 敏感路径写入被拦截（无 UI 无法确认）: ${p}`,
    userDenied: (label) => `[smart-approve] 用户拒绝: ${label}`,
    promptIntro: "你是 shell 命令风险分析器。分析下面这条命令，给出风险评估。",
    promptContext: "会话上下文",
    promptRule: "检测到的行为",
    promptCommand: "命令",
    promptOutput: "输出 JSON，字段:",
    promptSummaryDesc: "一句话中文总结命令在做什么",
    promptDetailDesc: "中文，50字内说明风险点和注意事项",
    promptRecommendDesc: "中文，是否建议执行 (yes/no/depends)",
    promptOnlyJson: "只输出 JSON，不要其他文字。",
    sessionAllow: "本次会话允许",
    permanentAllow: "永久允许",
    rememberQuestion: "记住此决策？",
    configLoaded: (p) => `[smart-approve] 配置已加载: ${p}`,
    configError: (p) => `[smart-approve] 配置加载失败，使用默认: ${p}`,
  },
  en: {
    analyzing: "⚡ Analyzing command risk with model…",
    confirmTitle: (label) => `⚠️ Dangerous command: ${label}`,
    confirmPathTitle: (p) => `⚠️ Protected path: ${p}`,
    risk: "Risk",
    summary: "Summary",
    detail: "Detail",
    recommend: "Recommendation",
    command: "Command",
    filePath: "File",
    allowPrompt: "Allow execution?",
    analysisUnavailable: "(model analysis unavailable)",
    blockedNoUI: (label) => `[smart-approve] Dangerous command blocked (no UI to confirm): ${label}`,
    blockedPathNoUI: (p) => `[smart-approve] Protected path write blocked (no UI to confirm): ${p}`,
    userDenied: (label) => `[smart-approve] User denied: ${label}`,
    promptIntro: "You are a shell command risk analyzer. Analyze the following command and provide a risk assessment.",
    promptContext: "Session context",
    promptRule: "Detected behaviors",
    promptCommand: "Command",
    promptOutput: "Output JSON with fields:",
    promptSummaryDesc: "One sentence summarizing what the command does",
    promptDetailDesc: "Within 50 words, explain risk points and precautions",
    promptRecommendDesc: "Whether to proceed (yes/no/depends)",
    promptOnlyJson: "Output JSON only, no other text.",
    sessionAllow: "Allow for this session",
    permanentAllow: "Always allow",
    rememberQuestion: "Remember this decision?",
    configLoaded: (p) => `[smart-approve] Config loaded: ${p}`,
    configError: (p) => `[smart-approve] Config load failed, using defaults: ${p}`,
  },
};

/** Bilingual label helper. */
export function makeLabel(en: string, zh: string): { en: string; zh: string } {
  return { en, zh };
}

/** Extract "zh" or "en" from a locale string like "zh_CN.UTF-8", "en_US", "C". */
export function parseLocale(loc: string): Lang | null {
  if (!loc) return null;
  const lower = loc.toLowerCase();
  if (lower.startsWith("zh")) return "zh";
  if (lower.startsWith("en")) return "en";
  return null;
}

/** Detect user language: "zh" or "en". Cross-platform (macOS + Linux). */
export function detectLang(): Lang {
  const env = process.env;
  const loc = env.LC_ALL || env.LC_MESSAGES || env.LANG || "";
  const lang = parseLocale(loc);
  if (lang) return lang;
  if (process.platform === "darwin") {
    try {
      const { execSync } = require("child_process");
      const apple = execSync("defaults read .GlobalPreferences AppleLocale", {
        encoding: "utf-8",
        timeout: 2000,
        stdio: ["pipe", "pipe", "ignore"],
      }).trim();
      return parseLocale(apple) || "en";
    } catch {
      return "en";
    }
  }
  return "en";
}

/** Resolve the active i18n bundle for the given (or detected) language. */
export function getI18n(lang: Lang): I18nLang {
  return I18N[lang] || I18N.en;
}
