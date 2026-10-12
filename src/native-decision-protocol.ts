import type { RiskAnalysis } from "./types";
import type { I18n } from "./i18n";

const RISK_CHOICES = ["low", "medium", "high"] as const;
const RECOMMEND_CHOICES = ["allow", "deny"] as const;

export interface NativeDecisionInput {
  subject: string;
  subjectLabel: string;
  behaviorLabels: string[];
  contextSection: string;
}

export type NativeDecisionState = Record<string, string | string[]>;

export interface NativeDecisionChoiceQuestion {
  type: "choice";
  instructions: string;
  criteria: Record<string, string>;
}

export type NativeDecisionQuestions = Record<string, NativeDecisionChoiceQuestion>;

/** Owns the host-neutral state, typed questions, and answer mapping. */
export class NativeDecisionProtocol {
  state(input: NativeDecisionInput): NativeDecisionState {
    return {
      contextSection: input.contextSection,
      detectedBehaviors: input.behaviorLabels,
      subjectLabel: input.subjectLabel,
      commandOrCode: input.subject,
    };
  }

  questions(t: I18n): NativeDecisionQuestions {
    const decision = t.nativeDecision;
    return {
      risk: {
        type: "choice",
        instructions: `${decision.classifyOnly} ${decision.riskInstructions}`,
        criteria: {
          low: decision.riskLow,
          medium: decision.riskMedium,
          high: decision.riskHigh,
        },
      },
      recommend: {
        type: "choice",
        instructions: `${decision.classifyOnly} ${decision.recommendationInstructions}`,
        criteria: {
          allow: decision.allow,
          deny: decision.deny,
        },
      },
    };
  }

  parse(result: unknown): RiskAnalysis | null {
    if (
      typeof result !== "object"
      || result === null
      || Array.isArray(result)
      || !("answers" in result)
    ) {
      return null;
    }
    const answers = result.answers;
    if (
      typeof answers !== "object"
      || answers === null
      || Array.isArray(answers)
      || !("risk" in answers)
      || !("recommend" in answers)
    ) {
      return null;
    }

    const riskAnswer = answers.risk;
    const recommendAnswer = answers.recommend;
    if (
      typeof riskAnswer !== "object"
      || riskAnswer === null
      || Array.isArray(riskAnswer)
      || !("type" in riskAnswer)
      || !("choice" in riskAnswer)
      || typeof recommendAnswer !== "object"
      || recommendAnswer === null
      || Array.isArray(recommendAnswer)
      || !("type" in recommendAnswer)
      || !("choice" in recommendAnswer)
      || riskAnswer.type !== "choice"
      || recommendAnswer.type !== "choice"
      || typeof riskAnswer.choice !== "string"
      || typeof recommendAnswer.choice !== "string"
    ) {
      return null;
    }

    const risk = RISK_CHOICES.find((candidate) => candidate === riskAnswer.choice);
    const recommend = RECOMMEND_CHOICES.find((candidate) => candidate === recommendAnswer.choice);
    if (!risk || !recommend) return null;

    // Preserve contradictions: AutoDecisionPolicy blocks high risk even when
    // the model recommends allow.
    return { risk, recommend };
  }
}
