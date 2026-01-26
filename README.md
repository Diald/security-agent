Security Agent (v1.0) 🛡️
An automated security vulnerability finder, the agent takes a github url as an input parameter and scans the repository on the following bases - 
1. SAST scanning - Bandit scanner - scans for
2. SCA scanning - OSV Parser - scans for vulnerable dependencies
3. Secret scanning - Trufflehog - scans for leaked keys


The high level idea is that the repo clones the provided github repo link, stores it temporarily in tmp/ folder, performs the required scans and then generates the llm response and remediation steps and then deleted the repo clone from tmp/ folder, the future considerations for this project is to use a better logic for this, and make use of scanning through api instead of having something like DiDn structure.

Prerequisites- 
Python 3.10+
cd security-agent
Set up a virtual environment:Bashpython -m venv env
# Windows:
.\env\Scripts\activate
# Linux/Mac:
source env/bin/activate

Install dependencies:Bashpip install -r requirements.txt

Configure environment variables:Create a file named variables.env in the root directory and add your Gemini API key:Code snippetGEMINI_API_KEY=your_api_key_here

🚀 UsageTo start a scan, simply run the main script. You can modify the REPO_URL inside main.py to target any public GitHub repository.Bashpython main.py

What happens next:Clone: The RepoManager clones the target repo to a temporary directory.Scan: Bandit, OSV, and TruffleHog run in parallel/sequence.Normalize: Findings are unified into a standard JSON format.Evaluate: The RiskEngine calculates a base security score.AI Analysis: Gemini reviews the findings and outputs a markdown report with remediation steps.Cleanup: The cloned repository is deleted to save space.

📂 Project StructurePlaintextsecurity-agent/
├── core/               # Contains pydantic models and repository cloning algorithm
├── scanners/           # Logic for Bandit, OSV, and TruffleHog runners and parsers
├── normalizers/        # Converters to transform tool output into a unified schema
├── engine/             # Risk scoring based on the findings
├── llm/                # Gemini client and prompt engineering templates
├── report/             # Markdown and JSON report generators
├── main.py             # Application entry point
└── requirements.txt    # Project dependencies
🛡️ Example AI OutputThe agent doesn't just list bugs; it provides:Overall Security Posture: (e.g., "Critical - Immediate action required")Release Readiness: (e.g., "BLOCKED - High risk of SQL injection")Actionable Remediation: Specific code snippets to fix the identified vulnerabiliti
