/** OMP supplies the native judgment API; Pi loads the generic entry instead. */
import { createNativeJudge, isJudgmentApi } from "@oh-my-pi/pi-ai";
import smartApprove from "./index";
import type { ExtensionAPI } from "./types";

export default function ompSmartApprove(pi: ExtensionAPI): void {
  smartApprove(pi, { createNativeJudge, isJudgmentApi });
}
