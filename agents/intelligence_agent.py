import os
from openai import OpenAI

client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

class IntelligenceAgent:

    def analyze(self, vulnerability, evidence):

        prompt = f"""
Analyze vulnerability and validation evidence.

Provide:
- Risk score (1-10)
- Confidence level
- OWASP category
- CWE mapping
- False positive likelihood

Vulnerability:
{vulnerability}

Evidence:
{evidence}
"""

        r = client.chat.completions.create(
            model="gpt-4.1",
            messages=[{"role": "user", "content": prompt}]
        )

        return r.choices[0].message.content
