from openai import OpenAI

client = OpenAI()

def level_three(model, message):
    return client.chat.completions.create(model=model, messages=[{"content": message}])

def level_two(model, message):
    return level_three(model, message)

def level_one():
    return level_two("wrapped-private-v2", "Review this harmless wrapper fixture.")

level_one()
