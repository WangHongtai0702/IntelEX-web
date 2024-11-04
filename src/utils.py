import json
import os
import logging
import random
import openai
import tiktoken
from pyvis.network import Network
from src.data import TACTICS

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    handlers=[
                        logging.StreamHandler()  # 日志输出到控制台
                    ])


def check_json_format(json_string, json_template):
    try:
        json_object = json.loads(json_string)
    except json.JSONDecodeError:
        logging.error(f"Invalid JSON format!, {json_string}")
        return False
    for key in json_template:
        if key not in json_object:
            return False
    return True


def add_line_breaks(input_string, interval=50):
    # Insert a newline character every 'interval' characters
    return '\n'.join([input_string[i:i + interval] for i in range(0, len(input_string), interval)])


def draw_ttp_tree(ttps: list):
    net = Network(height="800px", width="100%", directed=True)
    # 提取相同tactic下的technique，并生成nodes
    tactic_technique_map = {}
    all_nodes = []
    for tactic in TACTICS:
        tactic_group = [ttp for ttp in ttps if ttp['tactic'] == tactic]
        nodes = []
        if not tactic_group:
            continue
        for ttp in tactic_group:
            procedures = add_line_breaks('\n'.join(ttp['procedure']))
            entity = ', '.join(ttp['entity'])
            reason = add_line_breaks(ttp['reason'])
            title = f'''Procedure: \n{procedures}\n\nEntity: \n{entity}\n\nReason: \n{reason}'''
            node = {"id": ttp['technique'], "label": ttp['technique'], "title": title}
            nodes.append(node)
        tactic_technique_map[tactic] = nodes
        all_nodes.extend(nodes)

    # 生成树结点
    tree_data = {}
    exist_tactics = tactic_technique_map.keys()
    exist_tactics = sorted(exist_tactics, key=lambda x: TACTICS.index(x))
    root_node = None
    # 生成tactic节点作为subtitle
    for i, tactic in enumerate(exist_tactics):
        net.add_node(tactic, label=tactic, level=i, physics=False, color="white",
                     title=f"Tactic: {tactic}", font={"size": 18, "color": "black"})
        pos_x = i * 300  # Adjust x position to the right
        if i == 0:
            pos_y = 0
        else:
            pos_y = net.get_node(exist_tactics[i - 1])['y']
        net.get_node(tactic)['x'] = pos_x
        net.get_node(tactic)['y'] = pos_y
        logging.info(f"Node {tactic} position: ({pos_x}, {pos_y})")
    for i, tactic in enumerate(exist_tactics):
        if i < len(exist_tactics) - 1:
            net.add_edge(tactic, exist_tactics[i + 1])
    for i, tactic in enumerate(exist_tactics):
        nodes = tactic_technique_map[tactic]
        if i == 0:
            root_node = nodes[0]
            for node in nodes[1:]:
                net.add_node(node['id'], level=0, label=node['label'], title=node['title'])
        if i != len(tactic_technique_map) - 1:
            tree_data[nodes[0]['id']] = [node['id'] for node in
                                         tactic_technique_map[exist_tactics[i + 1]]]  # 让每个的第一个成为下一个的父节点
    logging.info(f"Nodes data: {all_nodes}")
    logging.info(f"Tree data: {tree_data}")

    # 生成图
    def add_nodes_edges(parent, level, pos_x):
        parent_node = [n for n in all_nodes if n['id'] == parent][0]
        net.add_node(parent, label=parent, level=level, physics=False, title=parent_node['title'])
        random_color = "#{:06x}".format(random.randint(0xAAAAAA, 0xFFFFFF))
        if parent in tree_data:
            for index, child in enumerate(tree_data[parent]):
                child_node = [n for n in all_nodes if n['id'] == child][0]
                net.add_node(child, label=child, level=level + 1, physics=False, title=child_node['title'],
                             color=random_color)
                net.add_edge(parent, child)

                # Ensure all nodes at the same level are aligned vertically
                pos_x_child = pos_x + 300  # Adjust x position to the right
                pos_y_child = (index - len(tree_data[parent]) / 2) * 100  # Adjust y position
                net.get_node(child)['x'] = pos_x_child
                net.get_node(child)['y'] = pos_y_child

                # Recursively add children
                add_nodes_edges(child, level + 1, pos_x_child)

    add_nodes_edges(root_node['id'], 0, 0)

    net.set_options("""
            var options = {
              "layout": {
                "hierarchical": {
                  "enabled": true,
                  "direction": "LR",
                  "sortMethod": "directed"
                }
              },
              "edges": {
                "smooth": true
              }
            }
        """)
    net.save_graph("results/ttp_tree.html")


def truncate_input(input_text, max_tokens=127000):
    encoding = tiktoken.encoding_for_model(os.environ["MODEL_NAME"])
    tokens = encoding.encode(input_text)  # Tokenize the input text
    if len(tokens) > max_tokens:
        truncated_tokens = tokens[:max_tokens]  # Truncate tokens to the maximum allowed length
        truncated_text = encoding.decode(truncated_tokens)  # Decode the truncated tokens back into text
        return truncated_text
    return input_text


def extract_report_from_log(log_path):
    client = openai.OpenAI(api_key=os.environ["OPENAI_API_KEY"])
    with open(log_path, 'r', encoding='utf-8') as f:
        log = f.read()
    system_prompt = f'''
    You are a security analyst working for a cybersecurity company. 
    You have been tasked with analyzing a network log file from a honeypot. The log file contains information about a potential cyber attack. Your job is to extract the relevant information from the log file and write a report detailing.
    Below is the instruction for the task:
    - Analyze the log file and extract the relevant information.
    - Extract as much as IoCs as possible.
    - Note that the extracted report will be used to generate sigma rules for the intrusion detection system.
    - The log file may contain several attacks, ensure to extract all the relevant information.
    - The report should be detailed and well-structured, including sequence of attack behaviors.
    '''
    user_prompt = f'''
    The log file is in csv format and contains the following columns: date, time, url, user_agent, source.
    The log file content is as follows:
    {log}
    '''
    processed_user_prompt = truncate_input(user_prompt)

    messages = [{'role': 'system', 'content': system_prompt},
                {'role': 'user', 'content': processed_user_prompt}]
    response = client.chat.completions.create(
            model=os.environ["MODEL_NAME"],
            messages=messages,
        )
    report = response.choices[0].message.content
    return report
