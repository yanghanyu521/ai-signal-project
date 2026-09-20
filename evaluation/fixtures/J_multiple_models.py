from openai import OpenAI

client = OpenAI()
client.chat.completions.create(model="model-alpha", messages=[{"content": "Classify harmless input A."}])
client.chat.completions.create(model="model-beta", messages=[{"content": "Classify harmless input B."}])
