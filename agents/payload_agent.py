import os
from openai import OpenAI

client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

class PayloadAgent:

    def generate(self, vulnerability):

        prompt = f"""
Generate safe test payloads to verify this vulnerability:

{vulnerability['name']}
"""

        response = client.chat.completions.create(
            model="gpt-4.1",
            messages=[{"role": "user", "content": prompt}]
        )

        return [
            p.strip()
            for p in response.choices[0].message.content.split("\n")
            if p.strip()
        ]
