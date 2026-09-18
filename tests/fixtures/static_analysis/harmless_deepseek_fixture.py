def run(client):
    return client.invoke({
        "deployment": "harmless-nebula-v9",
        "dialog": [
            {"speaker": "human", "body": "Summarize this harmless test record."},
        ],
    })
