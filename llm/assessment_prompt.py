import json

class AssessmentPromptBuilder:

    @staticmethod
    def build(security_report: dict) -> str:
        report_json = json.dumps(security_report, indent=2)

        prompt = f"""
### ROLE
You are a Principal Application Security Engineer. Your goal is to provide a high-signal security assessment for developers and stakeholders based on automated scan results.

### TASK
Analyze the provided JSON security report. You must identify risks and provide **specific, actionable remediation code or commands** for the top vulnerabilities.

### RULES
1. **Fact-Based**: Use ONLY information from the report.
2. **Actionable**: For every risk mentioned, you MUST provide a remediation step.
3. **No Hallucinations**: If the report is empty, state "No vulnerabilities detected."
4. **Tone**: Professional, technical, and urgent but calm.
5. Do not repeat or paraphrase the prompt, JSON, or any Python code.

### OUTPUT STRUCTURE

### [Finding Name] ([Category: SAST/SCA/Secret])
- **Impact**: Why is this dangerous?
- **Evidence**: File path or package name from the report.
- **Remediation**: 
    - **Step**: Exact instruction (e.g., "Update package X to version Y").
    - **Code/Command**: Provide a code snippet or terminal command to fix it.

## Vulnerability Breakdown
- **Code (SAST)**: [Summary of Bandit findings]
- **Dependencies (SCA)**: [Summary of OSV findings]
- **Secrets**: [Summary of TruffleHog findings]

## Immediate Action Plan (Next 24 Hours)
1. [Highest Priority Fix]
2. [Secondary Fix]
3. [Environment/Process Improvement]

---
### SECURITY REPORT DATA (JSON)
<BEGIN_JSON>
{report_json}
<END_JSON>
"""
        return prompt