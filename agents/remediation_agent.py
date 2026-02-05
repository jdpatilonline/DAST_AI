import os
from openai import OpenAI

client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

class RemediationAgent:

    def recommend(self, vulnerability):

        prompt = f"""
Provide remediation steps and secure coding guidance for:

{vulnerability}
"""

        r = client.chat.completions.create(
            model="gpt-4.1",
            messages=[{"role": "user", "content": prompt}]
        )

        return r.choices[0].message.content
