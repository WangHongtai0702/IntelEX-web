import openai
import json
import pandas as pd
import logging
from dotenv import load_dotenv
import os

load_dotenv('../.env')
logging.basicConfig(level=logging.INFO)


def prepare_train_data():
    df = pd.read_csv('../input/techniques.csv')
    with open('../dataset/finetune/techniques.jsonl', 'w') as f:
        for i in range(len(df)):
            technique = df.iloc[i]['title']
            description = df.iloc[i]['text']
            tactic = df.iloc[i]['tactics']
            formatted_data = {
                "messages": [
                    {"role": "system", "content": f"You are a helpful assistant for a cybersecurity analyst."},
                    {"role": "user", "content": f"Describe {technique}"},
                    {"role": "assistant",
                     "content": f"The description of {technique}: {description}. This technique belongs to {tactic} tactic."},
                ]
            }
            f.write(json.dumps(formatted_data) + '\n')
    logging.info('Data preparation completed!')


def upload_dataset():
    logging.info('Uploading dataset')
    client = openai.OpenAI(api_key=os.environ["OPENAI_API_KEY"])
    client.files.create(
        purpose="fine-tune",
        file=open("../dataset/finetune/techniques.jsonl", "rb"),
    )
    logging.info('Upload completed!')


def finetune_model():
    client = openai.OpenAI(api_key=os.environ["OPENAI_API_KEY"])
    client.fine_tuning.jobs.create(
        model="gpt-4o-mini-2024-07-18",
        training_file="file-nrW1EJ0OWyeTngl4TVkhw4Y8",
    )


if __name__ == '__main__':
    client = openai.OpenAI(api_key=os.environ["OPENAI_API_KEY"])
    print(client.fine_tuning.jobs.list(limit=10))
    print(client.fine_tuning.jobs.retrieve("ftjob-UG71Hv3gzIDdJYcbvBElOYaz"))

# ft:gpt-4o-mini-2024-07-18:personal::A4MXr8Ap
