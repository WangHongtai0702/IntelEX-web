import os

import openai
import json
import shlex
import subprocess
import logging
import time

import pandas as pd
from dotenv import load_dotenv
from pprint import pprint
from src.data import TACTIC_TECHNIQUES_MAPPING, TACTIC_DESCRIPTION
from nltk.tokenize import sent_tokenize
from src.rag import rag_search

load_dotenv()

# os.environ["MODEL_NAME"] = 'ft:gpt-4o-mini-2024-07-18:personal::A4MXr8Ap'
# os.environ["MODEL_NAME"] = 'o1-mini'

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    handlers=[
                        logging.FileHandler("../output.log"),  # 日志保存到文件
                        logging.StreamHandler()  # 日志输出到控制台
                    ])


def analyse_technique(attack_report: str, rag_result: list) -> dict:
    """
    Analyse the tactics used in the attack report(part of the report)
    :param rag_result:
    :param attack_report:
    :return:
    """
    client = openai.OpenAI(api_key=os.environ["OPENAI_API_KEY"])
    prompt_tokens = 0
    completion_tokens = 0
    system_prompt = f"""
    You are a helpful assistant for a cybersecurity analyst.
    You will be given a cyber threat intelligence (CTI) report. You need to analyse the techniques used in the attack.
    A CTI report usually contains tactics, techniques, and procedures (TTPs) used by adversaries.
    The tactic and technique are defined by MITRE ATT&CK.
    Tactics represent the "why" of an ATT&CK technique or sub-technique. It is the adversary's tactical goal: the reason for performing an action. For example, an adversary may want to achieve credential access.
    Techniques represent 'how' an adversary achieves a tactical goal by performing an action. For example, an adversary may dump credentials to achieve credential access.
    Below is the Tactics names and descriptions:
    {TACTIC_DESCRIPTION}
    Below are all the tactics and the techniques they contain:
    {TACTIC_TECHNIQUES_MAPPING}
    
    Below is the instruction to finish the task:
    - You need to analyse the techniques used in the attack.
    - Make sure that the techniques are one of the techniques above.
    - The output needs to be in JSON format.
    The output format is as follows:
    {{
        "technique": ["TECHNIQUE NAME1", "TECHNIQUE NAME2", ...]
    }}
    """

    user_prompt = f"""
    The report is as follows:
    {attack_report}
    """
    messages = [{"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}, ]
    response = client.chat.completions.create(
        model=os.environ["MODEL_NAME"],
        messages=messages,
        response_format={"type": "json_object"}
    )
    try:
        technique_result = json.loads(response.choices[0].message.content)
    except Exception as e:
        logging.error(f"Error: {e}")
        logging.error(f"Response: {response.choices[0].message.content}")
        technique_result = {"technique": []}
    prompt_tokens += response.usage.prompt_tokens
    completion_tokens += response.usage.completion_tokens

    # rag_techniques = [rag['technique'] for rag in rag_result]
    # technique_result['technique'].extend(rag_techniques)
    # return technique_result

    messages.append({"role": "assistant", "content": f"Techniques: {technique_result['technique']}"})
    system_prompt = f"""
    You are a helpful assistant for a cybersecurity analyst.
    The user will provide another possible technique and description.
    Your task is to determine whether the technique exists in the report.
    Below is the instruction to finish the task:
    - You need to verify whether the technique exists in the report.
    - If the technique exists in the report, you need to output YES and the reason.
    - If the technique does not exist in the report, you need to output NO and the reason.
    - The output needs to be in JSON format.
    The output format is as follows:
    {{"if_exist": "YES/NO", "reason": "REASON"}}
    """
    messages.append({"role": "system", "content": system_prompt})
    without_rag_without_filter_technique = {}
    for technique in technique_result['technique']:
        without_rag_without_filter_technique[technique] = "No reason"
    technique_result['technique'].extend(result['technique'] for result in rag_result)
    exclude_techniques = []
    with_rag_without_filter_technique = {}
    for technique in technique_result['technique']:
        with_rag_without_filter_technique[technique] = "No reason"
    with_rag_with_filter_technique = {}
    for i in range(len(technique_result['technique']) - 1, -1, -1):  # 反向遍历来pop
        technique = technique_result['technique'][i]
        description = get_description(technique)
        user_message = {"role": "user",
                        "content": f"Possible technique: {technique} \nDescription:{description}"}
        messages.append(user_message)
        response = client.chat.completions.create(
            model=os.environ["MODEL_NAME"],
            messages=messages,
            response_format={"type": "json_object"}
        )
        try:
            result = json.loads(response.choices[0].message.content)
        except Exception as e:
            logging.error(f"Error: {e}")
            logging.error(f"Response: {response.choices[0].message.content}")
            result = {"if_exist": "NO", "reason": "Error"}
        prompt_tokens += response.usage.prompt_tokens
        completion_tokens += response.usage.completion_tokens
        if result['if_exist'] == "YES":
            with_rag_with_filter_technique[technique] = result['reason']
        else:
            logging.info(f"[{technique}] does not exist in the report, reason: {result['reason']}")
            exclude_techniques.append(f"[{technique}] does not exist in the report, reason: {result['reason']}")
            technique_result['technique'].pop(i)
        messages.pop()

    return {"without_rag_without_filter_technique": without_rag_without_filter_technique,
            "with_rag_without_filter_technique": with_rag_without_filter_technique,
            "with_rag_with_filter_technique": with_rag_with_filter_technique,
            "exclude_techniques": exclude_techniques,
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens}
    # error detect


def get_description(technique):
    df = pd.read_csv('input/techniques.csv')
    description = df[df['title'] == technique]['text'].values
    if len(description) == 0:
        logging.error(f"Cannot find the description of the technique: {technique}")
        return ""
    else:
        # logging.info(f"Technique: {technique}, Description: {description}")
        first_para = description[0].split('\n')[0]
        return first_para


def judge_if_exist(attack_report, technique):
    client = openai.OpenAI(api_key=os.environ["OPENAI_API_KEY"])
    system_prompt = f"""
    You are a helpful assistant for a cybersecurity analyst.
    The user will provide another possible technique and description.
    Your task is to determine whether the technique exists in the report.
    Below is the instruction to finish the task:
    - You need to verify whether the technique exists in the report.
    - The techniques are found by human based on MITRE ATT&CK.
    - If the technique exists in the report, you need to output YES and the reason. Also, you need to provide the related part of the report in reason.
    - If the technique does not exist in the report, you need to output NO and the specific reason.
    - If the result is NO, the reason you provide should be convincing, and the reason should be related to the content of the report. Because they are all human-generated.
    - The output needs to be in JSON format.
    The output format is as follows:
    {{"if_exist": "YES/NO", "reason": "REASON"}}
    """
    technique_description = get_description(technique)
    user_prompt = f"""
    The report is as follows:
    {attack_report}
    The possible technique is:
    {technique}
    The description of the technique is:
    {technique_description}
    """
    messages = [{"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}, ]
    response = client.chat.completions.create(
        model=os.environ["MODEL_NAME"],
        messages=messages,
        response_format={"type": "json_object"}
    )
    try:
        return json.loads(response.choices[0].message.content)
    except Exception as e:
        logging.error(f"Error: {e}")
        logging.error(f"Response: {response.choices[0].message.content}")
        return {"if_exist": "NO", "reason": "Error"}


def _extract_related_report(attack_report, technique):
    client = openai.OpenAI(api_key=os.environ["OPENAI_API_KEY"])
    system_prompt = f"""
    You are a helpful assistant for a cybersecurity analyst.
    You will be given a cyber threat intelligence (CTI) report.
    You need to extract the related part of the report based on the tactic and technique used in the attack.
    
    Below is the instruction to finish the task:
    - You only need to extract the related part of the report based on the tactic and technique and give the original text.
    - Do not generate irrelevant content.
    - Your output should be part of the original report. These parts can be continuous or discontinuous.
    """

    user_prompt = f"""
    The cyber threat intelligence report is as follows:
    {attack_report}
    In the CTI report, the part related to the technique "{technique}" is:
    """
    messages = [{"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}, ]
    response = client.chat.completions.create(
        model=os.environ["MODEL_NAME"],
        messages=messages,
    )
    logging.info(f"Extracted report: {response.choices[0].message.content}")
    return response.choices[0].message.content


def analyse_procedure(entire_report, technique):
    attack_report = _extract_related_report(entire_report, technique)
    # attack_report = entire_report
    client = openai.OpenAI(api_key=os.environ["OPENAI_API_KEY"])
    prompt = f"""
    Analyse the implementation details taken by the attacker to achieve their goal.
    The procedure usually contains entities, actions, and relationships.
    You need to focus on the entities mostly.
    For example, the entities can be following:
    - IP addresses or domain names such as 168.0.0.1, example.com
    - File names or hashes such as ctfhost2.exe
    - Programs or software names such as Mimikatz, vssadmin.exe
    - And so on
    The report is as follows:
    {attack_report}
    
    The technique used in the attack is {technique}.
    
    """
    cmd = ["python", "-m", "graphrag.query", "--root", ".", "--method", "global", shlex.quote(prompt)]

    result = subprocess.run(cmd, capture_output=True, text=True, check=True)
    output = result.stdout

    # 提取 "SUCCESS: Local Search Response:" 之后的内容
    graphrag_response = output.split("SUCCESS: Global Search Response:", 1)[-1].strip()
    logging.info(f"GraphRAG result: {graphrag_response}")
    system_prompt = f"""
    You are a helpful assistant for a cybersecurity analyst.
    Your task is to extract procedures and transform it into a structured format.
    The procedure is the steps taken by the attacker to achieve their goal.
    The procedure usually contains entities, actions, and relationships.
    Below is an example of one possible procedure:
    Hikit has been spread through spear phishing emails.
    
    Below is the instruction to finish the task:
    - Do not extract the tactic and technique used in the attack, only the procedure.
    - The results need to be presented in a clear format, preferably in paragraphs.
    - Each procedure should conform to the format of the procedure: <entity> <relationship> <action>
    - Use 1, 2, 3, 4, 5 ... to list the steps.
    - You need to pay most attention to IoCs(Indicators of Compromise) and entities.
    - The output needs to be in JSON format.
    The output format is as follows:
    {{
        "procedure": ["1. PROCEDURE1", "2. PROCEDURE2", "3. PROCEDURE3", ...]
    }}
    
    """
    user_prompt = f"""
    The original report is as follows:
    {attack_report}
    
    The analysis report is as follows:
    {graphrag_response}
    """
    messages = [{"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}, ]
    response = client.chat.completions.create(
        model=os.environ["MODEL_NAME"],
        messages=messages,
        response_format={"type": "json_object"}
    )
    return graphrag_response, json.loads(response.choices[0].message.content)


# only analyse tactic and technique
# todo: add the tactic analysis
def analyse_ttp(attack_report: str, if_procedure: bool) -> dict:
    # entity -> tactic -> technique
    logging.info("Start to analyse tactic and technique in the report")
    start_time = time.time()
    sentences = sent_tokenize(attack_report)
    # 超参数
    window_size = 3
    step_size = 1
    # 滑动窗口遍历
    ttps = {"exclude_techniques": [],
            "ttps_without_rag_without_filter": [],
            "ttps_with_rag_without_filter": [],
            "ttps_with_rag_with_filter": [],
            "usage": {"prompt_tokens": 0, "completion_tokens": 0},
            "time": 0}
    for i in range(1, len(sentences) - window_size + 1, step_size):
        sentence = sentences[i]
        window = "".join(sentences[i - 1:i + window_size - 1])
        rag_result = rag_search(sentence)
        entity, prompt_tokens, completion_tokens = analyse_named_entities(sentence)
        ttps['usage']['prompt_tokens'] += prompt_tokens
        ttps['usage']['completion_tokens'] += completion_tokens
        if entity['entity']:
            logging.info(f"Named entity: {entity}")
            analyse_technique_result = analyse_technique(window, rag_result)
            prompt_tokens = analyse_technique_result['prompt_tokens']
            completion_tokens = analyse_technique_result['completion_tokens']
            exclude_technique = analyse_technique_result['exclude_techniques']
            technique_without_rag_without_filter = analyse_technique_result['without_rag_without_filter_technique']
            technique_with_rag_without_filter = analyse_technique_result['with_rag_without_filter_technique']
            technique_with_rag_with_filter = analyse_technique_result['with_rag_with_filter_technique']
            ttps['usage']['prompt_tokens'] += prompt_tokens
            ttps['usage']['completion_tokens'] += completion_tokens
            ttps['exclude_techniques'].extend(exclude_technique)
            for key, value in technique_with_rag_with_filter.items():
                # if the technique is not a valid technique, skip
                tactic = get_tactic_by_technique(key)
                if tactic is None:
                    logging.error(f"[{key}] is not a technique in the dict")
                    continue
                ttp = {"technique": key, "reason": value, "procedure": [], "tactic": tactic, "entity": entity['entity']}
                if key in [item["technique"] for item in ttps["ttps_with_rag_with_filter"]]:
                    # if the technique is already in the list, skip
                    continue
                else:
                    # the first element is the technique, the second element is the procedure
                    if if_procedure:
                        _, procedure = analyse_procedure(window, key)
                        ttp["procedure"] = procedure["procedure"]
                    ttps["ttps_with_rag_with_filter"].append(ttp)
            for key, value in technique_with_rag_without_filter.items():
                # if the technique is not a valid technique, skip
                tactic = get_tactic_by_technique(key)
                if tactic is None:
                    logging.error(f"[{key}] is not a technique in the dict")
                    continue
                ttp = {"technique": key, "reason": value, "procedure": [], "tactic": tactic, "entity": entity['entity']}
                if key in [item["technique"] for item in ttps["ttps_with_rag_without_filter"]]:
                    # if the technique is already in the list, skip
                    continue
                else:
                    # the first element is the technique, the second element is the procedure
                    ttps["ttps_with_rag_without_filter"].append(ttp)
            for key, value in technique_without_rag_without_filter.items():
                # if the technique is not a valid technique, skip
                tactic = get_tactic_by_technique(key)
                if tactic is None:
                    logging.error(f"[{key}] is not a technique in the dict")
                    continue
                ttp = {"technique": key, "reason": value, "procedure": [], "tactic": tactic, "entity": entity['entity']}
                if key in [item["technique"] for item in ttps["ttps_without_rag_without_filter"]]:
                    # if the technique is already in the list, skip
                    continue
                else:
                    # the first element is the technique, the second element is the procedure
                    ttps["ttps_without_rag_without_filter"].append(ttp)
    end_time = time.time()
    total_time = end_time - start_time
    ttps['time'] = total_time
    logging.info(f'The total amount of technique is {len(ttps["ttps_with_rag_with_filter"])}, the total tokens is {ttps["usage"]}')
    logging.info("Finish analysing the ttps of the report")
    return ttps


def get_tactic_by_technique(technique):
    for tactic, techniques in TACTIC_TECHNIQUES_MAPPING.items():
        if technique in techniques:
            return tactic
    return None  # 如果没有找到，返回 None


def query_graphrag(query):
    cmd = ["python", "-m", "graphrag.query", "--root", ".", "--method", "local", shlex.quote(query)]

    result = subprocess.run(cmd, capture_output=True, text=True, check=True)
    output = result.stdout

    # 提取 "SUCCESS: Local Search Response:" 之后的内容
    graphrag_response = output.split("SUCCESS: Local Search Response:", 1)[-1].strip()
    return graphrag_response


def analyse_ioc(report_sentence):
    client = openai.OpenAI(api_key=os.environ["OPENAI_API_KEY"])
    system_prompt = f"""
        You are a helpful assistant for a cybersecurity analyst.
        You will be given a cyber threat intelligence (CTI) report.
        Your task is to extract the indicators of compromise (IoCs) from the following CTI report.
        
        Below is the instruction to finish the task:
        - The IoCs should include IP addresses, domain names, URLs, file hashes, etc.
        - Focus on terms that describe the nature of the attack, the software, or methods being used.
        - The output needs to be in JSON format.
        - If there is no IoC in the report, return an empty list.
        
        Below is an example of IoCs:
        Anomalous Outbound Traffic on the Network
        - Ip Address:
        - Domain Name:
        Unusual User Account Activity
        - file hash
        - URL
        
        The output format is as follows:
        {{"ioc": ["IOC1", "IOC2", ...]}}
        
    """
    user_prompt = f"""
            The cyber threat intelligence report is as follows:
            {report_sentence}
            """
    messages = [{"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}, ]

    response = client.chat.completions.create(
        model=os.environ["MODEL_NAME"],
        messages=messages,
    )
    try:
        return json.loads(response.choices[0].message.content), \
            response.usage.prompt_tokens, response.usage.completion_tokens
    except Exception as e:
        logging.error(f"Error: {e}")
        logging.error(f"Response: {response.choices[0].message.content}")
        return {"ioc": []}, response.usage.prompt_tokens, response.usage.completion_tokens


def analyse_named_entities(report_sentence):
    client = openai.OpenAI(api_key=os.environ["OPENAI_API_KEY"])
    system_prompt = f"""
        You are a helpful assistant for a cybersecurity analyst.
        You will be given a cyber threat intelligence (CTI) report.
        Your task is to extract the key entity from the following CTI report.

        Below is the instruction to finish the task:
        - The entity should include technical terms, specific vulnerabilities, attack methods, or components being exploited.
        - Focus on terms that describe the nature of the attack, the software, or methods being used.
        - The output needs to be in JSON format.
        - If there is no entity in the report, return an empty list.
        
        The output format is as follows:
        {{"entity": ["ENTITY1", "ENTITY2", "ENTITY3", ...]}}
        """

    user_prompt = f"""
        The cyber threat intelligence report is as follows:
        {report_sentence}
        """
    messages = [{"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}, ]

    response = client.chat.completions.create(
        model=os.environ["MODEL_NAME"],
        messages=messages,
    )
    try:
        return json.loads(
            response.choices[0].message.content), response.usage.prompt_tokens, response.usage.completion_tokens
    except Exception as e:
        logging.error(f"Error: {e}")
        logging.error(f"Response: {response.choices[0].message.content}")
        return {"entity": []}, response.usage.prompt_tokens, response.usage.completion_tokens


if __name__ == '__main__':
    report = """
    The threat actors sent the trojanized Microsoft Word documents, probably via email. Talos discovered a document named MinutesofMeeting-2May19.docx. Once the victim opens the document, it fetches a remove template from the actor-controlledwebsite, hxxp://droobox[.]online:80/luncher.doc. Once the luncher.doc was downloaded, it used CVE-2017-11882, to execute code
on the victim's machine. After the exploit, the file would write a series of base64-encoded PowerShell commands that actedas a stager and set up persistence by adding it to the HKCU\Software\Microsoft\Windows\CurrentVersion\Run Registry key.
    """
    report2 = 'Benign activity ran for most of the morning while the tools were being setup for the day.  The activity was modified so the hosts would open Firefox and browse to http://215.237.119.171/config.html.  The simulated host then entered URL for BITS Micro APT as http://68.149.51.179/ctfhost2.exe.   We used the exploited Firefox backdoor to initiate download of ctfhost2.exe via the Background Intelligent Transfer Service (BITS).  Our server indicated the file was successfully downloaded using the BITS protocol, and soon after Micro APT was executed on the target and connected out to 113.165.213.253:80 for C2.  The attacker tried to elevate using a few different drivers, but it failed once again due to the computer having been restarted without disabling driver signature enforcement.  BBN tried using BCDedit to permanently disable driver signing, but it did not seem to work during the engagement as the drivers failed to work unless driver signing was explicitly disabled during boot.'
    # result = judge_if_exist("Once SYSTEM, the attacker exfil’ed the host and network files as well as a passwd file in the home directory.","OS Credential Dumping")
    # pprint(result)
