import os
import json
import requests

MODEL = os.getenv("OLLAMA_MODEL", "mistral")
REPORT_DIR = "reports/ai"
os.makedirs(REPORT_DIR, exist_ok=True)


def ask_ai(prompt):
    """
    Ask Ollama AI for analysis, summary, or recommendations.
    """
    try:
        r = requests.post(
            "http://localhost:11434/api/generate",
            json={"model": MODEL, "prompt": prompt, "stream": False},
            timeout=600
        )
        return r.json().get("response", "No response from AI")
    except Exception as e:
        print("❌ AI request failed:", e)
        return "AI request failed"


def load_reports():
    """
    Load all JSON report files from reports directory, limit size to avoid huge prompts.
    """
    findings = []

    if not os.path.exists("reports"):
        print("❌ Reports directory not found. Skipping AI analysis.")
        return findings

    for root, _, files in os.walk("reports"):
        for f in files:
            if f.endswith(".json"):
                file_path = os.path.join(root, f)
                try:
                    with open(file_path) as file:
                        # Limit to first 3000 characters to avoid huge prompts
                        content = file.read()[:3000]
                        findings.append(content)
                except Exception as e:
                    print(f"❌ Failed to read {file_path}: {e}")

    return findings


def run():
    workspace = os.getcwd()

    # ----------------------------
    # Enterprise debug info
    # ----------------------------
    print("\n===== AI ANALYSIS ENTERPRISE =====")
    print("Workspace Path:", workspace)
    try:
        print("Workspace Files:", os.listdir(workspace))
        subprocess.run("ls -laR reports/ ", shell=True)
    except Exception as e:
        print("Error listing workspace files:", e)

    # ----------------------------
    # Load all previous reports
    # ----------------------------
    findings = load_reports()
    if not findings:
        print("⚠ No reports found to analyze. Skipping AI summary.")
        return

    # ----------------------------
    # Ask AI for executive summary
    # ----------------------------
    prompt_text = "Create executive vulnerability summary from the following findings:\n" + "\n".join(findings)
    try:
        summary = ask_ai(prompt_text)
    except Exception as e:
        print("❌ AI failed to generate summary:", e)
        summary = "AI analysis failed."

    # ----------------------------
    # Write executive summary
    # ----------------------------
    os.makedirs(REPORT_DIR, exist_ok=True)
    summary_file = os.path.join(REPORT_DIR, "executive_summary.txt")
    try:
        with open(summary_file, "w") as f:
            f.write(summary)
        print(f"✅ Executive summary written to {summary_file}")
        subprocess.run("ls -al reports/ai", shell=True)
    except Exception as e:
        print(f"❌ Failed to write executive summary: {e}")

    print("===== AI ANALYSIS COMPLETED =====\n")
