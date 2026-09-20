from openai import OpenAI

client = OpenAI()
DEPLOYMENT = "harmless-nebula-v9"
INSTRUCTION = "Summarize the supplied harmless test note."
client.chat.completions.create(model=DEPLOYMENT, messages=[{"role": "user", "content": INSTRUCTION}])
