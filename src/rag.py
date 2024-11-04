from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain_openai import OpenAIEmbeddings
import logging
from dotenv import load_dotenv
import os
import pandas as pd
from langchain_community.vectorstores import FAISS
from langchain.docstore.document import Document
from pprint import pprint

load_dotenv()
TEXT_SPLITTER = RecursiveCharacterTextSplitter(chunk_size=1024, chunk_overlap=200)


def save_to_vector_store():
    EMBEDDINGS = OpenAIEmbeddings(openai_api_key=os.environ["OPENAI_API_KEY"])
    db_path = f'../vector_db/techniques'
    file_path = f'../input/techniques.csv'
    df = pd.read_csv(file_path)
    chunks = []
    for i in range(len(df)):
        technique = df.iloc[i]['title']
        if ':' in technique:
            continue
        description = df.iloc[i]['text']
        doc = Document(page_content=f'''{technique}: {description}''', metadata={"source": "local"})
        chunks.append(doc)
    vector_store = FAISS.from_documents(chunks, EMBEDDINGS)
    vector_store.save_local(db_path)
    return vector_store


def rag_search(prompt):
    EMBEDDINGS = OpenAIEmbeddings(openai_api_key=os.environ["OPENAI_API_KEY"])
    vector_store = FAISS.load_local('vector_db/techniques', embeddings=EMBEDDINGS)
    docs = vector_store.similarity_search_with_score(prompt, k=3)  # 计算相似度，并把相似度高的chunk放在前面
    knowledge = [doc[0].page_content for doc in docs]  # 提取chunk的文本内容
    # logging.info(f'Knowledge: {knowledge}')
    techniques = []
    for k in knowledge:
        technique = k.split(':')[0]
        description = k.split(':')[1]
        first_para = description.split('\n')[0]
        # logging.info(f'Technique: {technique}')
        # logging.info(f'Description: {first_para}')
        techniques.append({'technique': technique, 'description': first_para})
    return techniques



if __name__ == '__main__':
    #save_to_vector_store()
    pprint(rag_search("Once SYSTEM, the attacker exfil’ed the host and network files as well as a passwd file in the home directory."))
