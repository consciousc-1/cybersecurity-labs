# macOS LaunchAgent Persistence — Detection to Containment

**Type:** Real incident (unplanned) · **Date:** 31 Oct 2026 · **Device:** personal MacBook (Apple Silicon)
**Tools:** Microsoft Defender for Endpoint, Defender XDR portal, macOS Terminal (`mdatp`, `launchctl`)
**Verdict:** True positive — malware (behavior consistent with macOS adware) · **Status:** Contained and eradicated

---

## Summary

While onboarding my Mac to Microsoft Defender for Endpoint for a SOC lab, real-time protection surfaced a **pre-existing infection**. A random-named LaunchAgent (`com.ekqutkgkxyxuonok`) was launching a hidden shell that executed AppleScript. Defender raised two alerts from the same root cause. I triaged both, confirmed the link through the process tree, quarantined the file, unloaded the persistence from launchd, verified no related artifacts remained, and closed the alerts with documented verdicts.

---

## Timeline (CET)

| Time | Event |
|---|---|
| ~20:18 | Mac onboarded; `mdatp health` showed `healthy: false` — event providers not running |
| ~20:25 | macOS system extensions approved → sensor fully active |
| 20:26 | **Alert:** Suspicious AppleScript activity (Medium) |
| 20:28 / 20:32 | Planned EICAR test detected and quarantined (pipeline check) |
| 20:32:55 | **Alert:** `Trojan:MacOS/SuspDecodeExec.A` — LaunchAgent plist quarantined |
| ~21:10 | Agent found still registered in launchd → unloaded with `launchctl bootout` |
| ~21:15 | Persistence locations reviewed; no further suspicious entries |
| ~21:47 | All alerts resolved and classified |

The first malicious activity appeared **one minute after the sensor became active**, so the infection predates the lab. Dwell time is unknown.

---

## Investigation

**1. Prioritization.** Three alerts in queue. The two "malware was prevented" alerts were already blocked; the **Medium** AppleScript alert was unresolved activity, so it was triaged first.

**2. Process tree** (AppleScript alert):

```
launchd → xpcproxy com.ekqutkgkxyxuonok → bash -c → osascript
```

`launchd` (macOS startup service) launched the random-named LaunchAgent, which opened a shell that ran AppleScript.

**3. Why a clean binary was still malicious.** `osascript` is Apple's own tool: Apple-signed, 0/51 on VirusTotal. The binary was legitimate; its **parent** was not. This is a living-off-the-land pattern — the verdict depends on what launched the tool, not the tool itself.

**4. Correlation.** The Trojan alert flagged the LaunchAgent **file**; the AppleScript alert flagged its **behavior**. One root cause, two detection angles — both linked in the case notes.

**5. Planned test vs. real finding.** The EICAR test produced `Virus:DOS/EICAR_Test_File`. The unexpected `Trojan:MacOS/SuspDecodeExec.A` detection is what triggered this investigation.

---

## Containment & Eradication

| Step | Action | Verification |
|---|---|---|
| 1 | Plist quarantined by Defender | `mdatp threat list` → `quarantined` |
| 2 | Agent still registered in launchd — quarantine alone did not remove it | `launchctl list \| grep ekq` returned the label |
| 3 | Unloaded: `launchctl bootout gui/$(id -u)/com.ekqutkgkxyxuonok` | Same check → no output |
| 4 | Reviewed `~/Library/LaunchAgents`, `/Library/LaunchAgents`, `/Library/LaunchDaemons` | Only known vendors (Adobe, Microsoft, Google, Zoom, Cold Turkey) |
| 5 | Reviewed browser extensions | All recognized, none suspicious |
| 6 | Full scan; re-checked detections | No further threats |
| 7 | Removed leftover VirtualBox LaunchAgent (unused software) | Attack-surface reduction |

---

## MITRE ATT&CK

| Tactic | Technique | Evidence |
|---|---|---|
| Persistence | **T1543.001** Launch Agent | `com.ekqutkgkxyxuonok` in LaunchAgents |
| Execution | **T1059.002** AppleScript | `bash -c → osascript` from the agent |

---

## Alert Classification

| Alert | Classification | Determination |
|---|---|---|
| Suspicious AppleScript activity | True positive | Malware |
| SuspDecodeExec malware was prevented | True positive | Malware |
| EICAR_Test_File malware was prevented | Informational, expected activity | Security testing |

---

## Lessons Learned

1. **New visibility exposes old compromises.** The infection existed before onboarding; it surfaced only once the sensor could see it.
2. **Quarantine ≠ eradication.** Removing the file left the launchd registration in place. Persistence must be unloaded and verified.
3. **Signed binaries can still be malicious activity.** Judge the process chain, not the file reputation.
4. **Severity ≠ importance.** The "Informational" Trojan alert pointed to the root cause of the Medium alert.
5. **Open gap — initial access not determined.** The entry vector (e.g., unofficial installer or fake update) was not identified. Next step would be reviewing install history around the agent's creation date.

---

## Screenshots

`/screenshots` — process tree, alert queue, `mdatp threat list`, launchd verification.
*Usernames, tenant ID, and organization ID are redacted.*

