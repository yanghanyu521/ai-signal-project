from openai import OpenAI

client = OpenAI(base_url="https://llm.invalid.example/v1")
client.chat.completions.create(
    model="private-router-alpha",
    messages=[{"role": "user", "content": "Label this harmless fixture."}],
)
