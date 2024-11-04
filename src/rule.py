import logging
import openai
import re
import yaml
import json
import os
from sigma.rule import SigmaRule
from sigma.backends.splunk import SplunkBackend
from sigma.pipelines.splunk import splunk_windows_pipeline
from sigma.backends.elasticsearch import LuceneBackend
from sigma.pipelines.elasticsearch import ecs_windows

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    handlers=[
                        logging.StreamHandler()  # 日志输出到控制台
                    ])


def generate_rules(report: str, ttps: list or None, rule_type: str) -> dict:
    # 生成规则
    logging.info("Generating rules...")

    client = openai.OpenAI(api_key=os.environ["OPENAI_API_KEY"])
    sys_prompt_for_network = f"""
    You are an expert in writing Sigma rules. For each attack description, write several Sigma rules to detect the relevant attacks.
    You will be given a CTI report and a TTP. You need to generate Sigma rules based on the TTP and the procedure examples.
    Below is the instruction for the task:
    - Your generated rules should be in YAML format.
    - Your generated rules should be diverse in nature, ensuring a wide variety of rules and reducing redundancy as much as possible.
    - The rules you generate need to catch as many malicious logs as possible, but they need to be specific. You cannot generate general rules.
    - Generate sigma rules as much as possible!
    - No explanation needed.
    - Do not generate any other irrelevant characters or words.
    - Do not generate "id" for the rule.
    - The fields in the sigma rule should only be 'user_agent', 'extracted_source', 'url', which means the selection should be based on these fields.
    
    Below is an example:
    ```yaml
    title: Detect Malicious HTTP Requests for Sensitive Files and IP Access
    status: experimental
    description: Detects malicious HTTP requests targeting sensitive files like .env, .git/config, or accessing direct IP addresses.
    author: YourName
    logsource:
      product: webserver
      service: http_access
    detection:
      selection:
        url:
          - '*.env'
          - '*.git/config'
          - 'http://*:*/*'
      condition: selection
    falsepositives:
      - Legitimate administrative access or automated scanners with permission.
    level: high
    tags:
      - attack.persistence
      - attack.discovery
      - attack.initial_access
      - attack.t1071.001
    fields:
      - url
      - user_agent
      - extracted_source
    ```
    """
    sys_prompt = f"""
    You are an expert in writing Sigma rules. For each attack description, write several Sigma rules to detect the relevant attacks.
    You will be given a CTI report and a TTP. You need to generate Sigma rules based on the TTP and the procedure examples.
    Below is the instruction for the task:
    - Your generated rules should be in YAML format.
    - Your generated rules should be diverse in nature, ensuring a wide variety of rules and reducing redundancy as much as possible.
    - The rules you generate need to catch as many malicious logs as possible, but they need to be specific. You cannot generate general rules.
    - You need to think about the extended operations of the attack to generate corresponding rules with extended meanings.
    - Generate sigma rules as much as possible!
    - No explanation needed.
    - Do not generate any other irrelevant characters or words.
    - Do not generate "id" for the rule.
    - Notice that the attack may through powershell, cmd or sysmon, etc. So you need to consider the log source and fields.
    
    #Example#
    ```yaml
    title: Potential Password Exposure (via cmdline)
    author: Adam Swan
    tags:
      - attack.t1552.001 
      - attack.credential_access
    logsource:
      product: windows
      category: process_creation
    detection:
      selection:
        Image|endswith: 
          - '\\notepad.exe'
          - '\word.exe'
          - '\excel.exe'
          - '\wordpad.exe'
          - '\\notepad++.exe'
        CommandLine|contains:
          - 'pass' #pass will match on password, including password is redundant
          - 'pwd'
          - 'pw.' #pw.txt, etc. 
          - 'account' #accounts, 
          - 'secret'
          - 'details' #I included plural details based on experience
      condition: selection
    ```
    ```yaml
    title: Suspicious PowerShell Web Request with Invoke-WebRequest in Message Field
    status: experimental
    description: Detects suspicious PowerShell Invoke-WebRequest commands with wildcard user-agent in the Message field.
    author: YourName
    logsource:
      product: windows
      service: powershell
    detection:
      selection:
        EventID: 4104
        Message|contains: 'Invoke-WebRequest'
        Message|contains: '-UserAgent "*<|>*"'
      condition: selection
    falsepositives:
      - Legitimate web requests using PowerShell for automation or administration tasks.
    level: high
    tags:
      - attack.t1071.001
      - attack.execution
      - attack.lateral_movement
    fields:
        - Message
        - EventID
    ```
    """

    rules = []
    attempts = 0
    prompt_tokens = 0
    completion_tokens = 0
    if not ttps:
        user_prompt = f'''
        CTI report:
        {report}
        '''
        messages = [{"role": "system", "content": sys_prompt},
                    {"role": "user", "content": user_prompt}, ]
        response = client.chat.completions.create(
            model=os.environ["MODEL_NAME"],
            messages=messages,
        )
        prompt_tokens += response.usage.prompt_tokens
        completion_tokens += response.usage.completion_tokens
        clean_rules_list, attempt = extract_sigma_rules(response.choices[0].message.content)
        attempts += attempt
        rules.extend(clean_rules_list)
    else:
        for i, ttp in enumerate(ttps):
            user_prompt = f'''
            CTI report:
            {report}
            
            TTP:
                Tactic: {ttp['tactic']}
                Technique: {ttp['technique']}
                Procedure: {ttp['procedure']}
            '''
            messages = [{"role": "system", "content": sys_prompt},
                        {"role": "user", "content": user_prompt}, ]
            response = client.chat.completions.create(
                model=os.environ["MODEL_NAME"],
                messages=messages,
            )
            prompt_tokens += response.usage.prompt_tokens
            completion_tokens += response.usage.completion_tokens
            clean_rules_list, attempt = extract_sigma_rules(response.choices[0].message.content)
            attempts += attempt
            rules.extend(clean_rules_list)
    logging.info(f"Generated {len(rules)} rules.")
    # 验证规则 & 转换规则
    converted_rules = []
    for i, rule in enumerate(rules):
        validated_sigma_rule = validate_sigma_rule(rule)
        if validated_sigma_rule:
            if rule_type == "splunk":
                converted_rule = convert_sigma_rule_to_splunk(validated_sigma_rule)
            elif rule_type == "elastic":
                converted_rule = convert_sigma_rule_to_elastic(validated_sigma_rule)
            else:
                converted_rule = None
            if converted_rule:
                converted_rules.extend(converted_rule)
            else:
                attempts += 1
        else:
            attempts += 1
    final_rules = []
    for rule in converted_rules:
        filter_result, prompt_token, completion_token = rule_filter(report, rule)
        prompt_tokens += prompt_token
        completion_tokens += completion_token
        filter_result['rule'] = rule
        final_rules.append(filter_result)
    return {"rules": final_rules,
            "sigma_rules": rules,
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "attempts": attempts}


def extract_sigma_rules(raw_data):
    pattern = r"```yaml(.*?)```"
    # 提取所有匹配
    result = []
    matches = re.findall(pattern, raw_data, re.DOTALL)
    attempts = 0

    def repair_yaml(wrong_yaml):
        nonlocal attempts
        max_attempts = 5
        client = openai.OpenAI(api_key=os.environ["OPENAI_API_KEY"])
        sys_prompt = f"""
        The following YAML is not valid. Please repair it.
        You ONLY need to generate the correct YAML format.
        Below is an example of your output:
```yaml
title: Deletion of Windows Volume Shadow Copies via Vssadmin
status: experimental
description: Detects the deletion of volume shadow copies using vssadmin command.
author: Expert SIGMA Agent
tags:
  - attack.t1490 
  - attack.impact
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: 
      - 'vssadmin.exe'
    CommandLine|contains:
      - 'delete shadows'
      - '/quiet'
  condition: selection
falsepositives:
  - Administrative activity
level: high
```
        """
        user_prompt = f"""
                            The incorrect YAML is:
                            {wrong_yaml}"""
        for i in range(max_attempts):
            messages = [{"role": "system", "content": sys_prompt},
                        {"role": "user", "content": user_prompt}]
            response = client.chat.completions.create(
                model=os.environ["MODEL_NAME"],
                messages=messages,
            )
            repaired_yaml = response.choices[0].message.content
            attempts += 1
            try:
                repaired_yaml = yaml.safe_load(re.findall(pattern, repaired_yaml, re.DOTALL)[0])
                return repaired_yaml
            except Exception as e:
                logging.error(f"Error in repairing YAML: {e}")
                user_prompt = f"""
                The incorrect YAML is:
                {wrong_yaml}
                The exception is:
                {e}"""
        return None

    for match in matches:
        try:
            # 使用yaml.safe_load来解析字符串
            parsed_data = yaml.safe_load(match)
            result.append(parsed_data)
        except yaml.YAMLError as exc:
            # 修复错误的YAML
            parsed_data = repair_yaml(match)
            if parsed_data:
                result.append(parsed_data)
            else:
                logging.error(f"Error in parsing YAML: {exc}")
    return result, attempts


def validate_sigma_rule(rule: dict) -> SigmaRule or None:
    try:
        sigma_rule = SigmaRule.from_dict(rule)
        return sigma_rule
    except Exception as e:
        logging.error(f"Error when validating Sigma rule: {e}")
        return None


def convert_sigma_rule_to_splunk(rule: SigmaRule) -> str or None:
    try:
        pipeline = splunk_windows_pipeline()
        backend = SplunkBackend(pipeline)
        splunk_rule = backend.convert_rule(rule)
        return splunk_rule
    except Exception as e:
        logging.error(f"Error when converting Sigma rule to Splunk: {e}")
        return None


def convert_sigma_rule_to_elastic(rule: SigmaRule) -> list or None:
    try:
        pipeline = ecs_windows()
        backend = LuceneBackend(pipeline)
        elastic_rule = backend.convert_rule(rule)
        return elastic_rule
    except Exception as e:
        logging.error(f"Error when converting Sigma rule to Elastic: {e}")
        return None


def rule_filter(report, rule):
    # 过滤规则
    client = openai.OpenAI(api_key=os.environ["OPENAI_API_KEY"])
    sys_prompt = f"""
    You are a cyber security analyst. Your task is to filter out irrelevant rules from the generated rules.
    You will be given a CTI report and a rule. You need to determine whether the rule is relevant to the CTI report.
    
    Below is the instruction for the task:
    - You should be very tough on the rules. If the rule is not relevant to the CTI report, you should filter it out.
    - If the rule is too general and does not match the CTI report, you need to filter it out.
    - If the rule should be kept, the "relevant" field should be set to "YES".
    - If the rule should be filtered out, the "relevant" field should be set to "NO".
    - The output format should be in JSON format.
    
    Below is the json format:
    {{"reason": "REASON", "relevant": "YES/NO"}}
    
    Below is an example:
    {{"reason": "The rule is too general and does not match the CTI report.", "relevant": "NO"}}
    """
    user_prompt = f"""
    CTI report:
    {report}
    Rule:
    {rule}
    """
    prompt_tokens = 0
    completion_tokens = 0
    messages = [{"role": "system", "content": sys_prompt},
                {"role": "user", "content": user_prompt}]
    response = client.chat.completions.create(
        model=os.environ["MODEL_NAME"],
        messages=messages,
        response_format={"type": "json_object"}
    )
    prompt_tokens += response.usage.prompt_tokens
    completion_tokens += response.usage.completion_tokens
    try:
        result = json.loads(response.choices[0].message.content)
        return result, prompt_tokens, completion_tokens
    except Exception as e:
        logging.error(f"Error in parsing JSON: {e}")
        return {"reason": "Error in parsing JSON", "relevant": "NO"}, prompt_tokens, completion_tokens


if __name__ == '__main__':
    # test
    pass
