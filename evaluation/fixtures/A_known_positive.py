from openai import OpenAI

client = OpenAI()
MODEL = "gpt-4o-mini"
PROMPT = "Classify this harmless synthetic record."
client.chat.completions.create(model=MODEL, messages=[{"role": "user", "content": PROMPT}])
