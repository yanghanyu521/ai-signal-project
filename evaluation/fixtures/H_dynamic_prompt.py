from openai import OpenAI

client = OpenAI()
PREFIX = "Summarize "
SUBJECT = "this harmless synthetic record."
PROMPT = PREFIX + SUBJECT
client.chat.completions.create(model="dynamic-model-v1", messages=[{"content": PROMPT}])
