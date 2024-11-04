import os
import json
import time
import logging
from src.ttp import judge_if_exist, analyse_ttp
from src.rule import generate_rules
import pandas as pd


def judge_if_contain_technique(content, techniques):
    results = []
    for technique in techniques:
        result = judge_if_exist(content, technique.strip())
        result['technique'] = technique
        results.append(result)
    return results


def refactor_dataset():
    dataset_path = '../dataset/CTI reports 1-8'
    labels_path = '../dataset/CTI reports 1-8 labels'
    results = {}
    for i, filename in enumerate(os.listdir(labels_path)):
        if filename.endswith(".txt"):
            label_path = os.path.join(labels_path, filename)
            with open(label_path, 'r', encoding='utf-8') as file:
                labels = file.readlines()
                print(labels)
                report_path = os.path.join(dataset_path, filename)
                with open(report_path, 'r', encoding='utf-8') as report_file:
                    report_content = report_file.read()
                    result = judge_if_contain_technique(report_content, labels)
                    results[filename] = result
    new_labels_path = '../results/new_labels.json'
    with open(new_labels_path, 'w', encoding='utf-8') as json_file:
        json.dump(results, json_file, ensure_ascii=False, indent=4)


def evaluate_ttp(dataset_path: str, if_procedure: bool = False) -> dict:
    results = {}
    start_time = time.time()
    for i, filename in enumerate(os.listdir(dataset_path)):
        # 检查文件是否是 .txt 文件
        if filename.endswith(".txt"):
            file_path = os.path.join(dataset_path, filename)
            # 读取文件内容
            with open(file_path, 'r', encoding='utf-8') as file:
                content = file.read()
                # 分析 TT
                try:
                    result = analyse_ttp(content, if_procedure=if_procedure)
                    results[filename] = result
                    logging.info(f'Finished processing {filename} ({i + 1}/{len(os.listdir(dataset_path))})!')
                except Exception as e:
                    logging.error(f'Error processing {filename}: {e}')
    end_time = time.time()
    logging.info(f'Finished processing all files in {end_time - start_time:.2f} seconds!')
    return results


def generate_ttps(dataset_path: str, if_procedure: bool = False) -> dict:
    results = {}
    start_time = time.time()
    current_time = time.strftime("%Y-%m-%d-%H-%M-%S", time.localtime())
    # Create a new directory using the current time
    new_dir = os.path.join('results/ttp_generation', current_time)
    os.makedirs(new_dir, exist_ok=True)
    # Save the content to a JSON file
    sorted_files = sorted(os.listdir(dataset_path))
    # after TALOS-2024-2062.txt data
    sorted_files = sorted_files[sorted_files.index('TALOS-2020-1206.txt'):]
    for i, filename in enumerate(sorted_files):
        # 检查文件是否是 .txt 文件
        if filename.endswith(".txt"):
            logging.info(f'Processing {filename} ({i + 1}/{len(os.listdir(dataset_path))})...')
            file_path = os.path.join(dataset_path, filename)
            # 读取文件内容
            with open(file_path, 'r', encoding='utf-8') as file:
                content = file.read()
                # 分析 TT
                try:
                    result = analyse_ttp(content, if_procedure=if_procedure)
                    results[filename] = result
                    with open(os.path.join(new_dir, f'talos_ttp.jsonl'), 'a', encoding='utf-8') as f:
                        f.write(json.dumps({filename: result}) + '\n')
                    logging.info(f'Finished processing {filename} ({i + 1}/{len(os.listdir(dataset_path))})!')
                except Exception as e:
                    logging.error(f'Error processing {filename}: {e}')
    end_time = time.time()
    logging.info(f'Finished processing all files in {end_time - start_time:.2f} seconds!')
    return results


def evaluate_rule_generation(dataset_path: str, with_ttp: bool, rule_type: str):
    results = {}

    for i, filename in enumerate(os.listdir(dataset_path)):
        start_time = time.time()
        # 检查文件是否是 .txt 文件
        if filename.endswith(".txt"):
            file_path = os.path.join(dataset_path, filename)
            # 读取文件内容
            with open(file_path, 'r', encoding='utf-8') as file:
                content = file.read()
                if with_ttp:
                    # 分析 TTP
                    ttps = analyse_ttp(content, if_procedure=True)
                    result = generate_rules(report=content, ttps=ttps['ttps_with_rag_with_filter'], rule_type=rule_type)
                else:
                    result = generate_rules(report=content, ttps=None, rule_type=rule_type)
                end_time = time.time()
                results[filename] = {"rules": result['rules'],
                                     "attempts": result['attempts'],
                                     "time": end_time - start_time,
                                     "prompt_tokens": result["prompt_tokens"],
                                     "completion_tokens": result["completion_tokens"]}
        logging.info(f'Finished processing {filename} ({i + 1}/{len(os.listdir(dataset_path))})!')
        yield {filename: result}


def evaluate_ttp_result(ttp_data: dict, ttp_type: str, labels_path: str) -> dict:
    result = {}
    total_input_tokens = 0
    total_output_tokens = 0
    total_time = 0
    for report_name, ttps in ttp_data.items():
        true_positive = 0
        false_positive = 0
        label_path = os.path.join(labels_path, report_name)
        with open(label_path, 'r', encoding='utf-8') as file:
            labels = file.readlines()
            if ',' in labels[0]:
                labels = [s.split(',')[0] for s in labels if s.split(',')[1].strip() != 'N']
            else:
                labels = [s.strip() for s in labels]
        for ttp in ttps[ttp_type]:
            if ttp['technique'] in labels:
                true_positive += 1
            else:
                false_positive += 1

        false_negative = len(labels) - true_positive
        result[report_name] = {
            'true_positive': true_positive,
            'false_positive': false_positive,
            'false_negative': false_negative
        }
        total_input_tokens += ttps['usage']['prompt_tokens']
        total_output_tokens += ttps['usage']['completion_tokens']
        total_time += ttps['time']
    result['usage'] = {
        'average_input_tokens': total_input_tokens / len(ttp_data),
        'average_output_tokens': total_output_tokens / len(ttp_data),
        'average_time': total_time / len(ttp_data)
    }
    # with open(f'results/ttp_evaluation/{os.path.basename(ttps_data_path)}', 'w', encoding='utf-8') as json_file:
    #     json.dump(result, json_file, ensure_ascii=False, indent=4)
    return result


def statistic_talos_ttps(data_paths: list) -> dict:
    result = {}
    total_reports = 0
    for data_path in data_paths:
        with open(data_path, 'r', encoding='utf-8') as file:
            ttps_data = file.readlines()
            print(f'Total reports in {data_path}: {len(ttps_data)}')
        for ttp_data in ttps_data:
            total_reports += 1
            ttp_data = json.loads(ttp_data)
            for report_name, ttps in ttp_data.items():
                ttps = ttps['ttps_with_rag_with_filter']
                for ttp in ttps:
                    if ttp['technique'] not in result:
                        result[ttp['technique']] = 1
                    else:
                        result[ttp['technique']] += 1
    # return top 10 techniques and their counts
    print(f'Total reports: {total_reports}')
    return dict(sorted(result.items(), key=lambda x: x[1], reverse=True)[:10])


def write_to_json_file(dic_path: str, file_name: str, contents: list) -> list:
    current_time = time.strftime("%Y-%m-%d-%H-%M-%S", time.localtime())
    # Create a new directory using the current time
    new_dir = os.path.join(dic_path, current_time)
    os.makedirs(new_dir, exist_ok=True)
    # Save the content to a JSON file
    file_paths = []
    for i, content in enumerate(contents):
        file_path = os.path.join(new_dir, f'{file_name}_{i}.json')
        with open(file_path, 'w', encoding='utf-8') as json_file:
            json.dump(content, json_file, ensure_ascii=False, indent=4)
        file_paths.append(file_path)
    return file_paths


def rule_json_to_csv(json_path: str, csv_path: str):
    with open(json_path, 'r', encoding='utf-8') as file:
        json_data = json.load(file)

    # Prepare data for CSV conversion
    csv_data = []

    for test_name, details in json_data.items():
        for rule in details['rules']:
            csv_data.append({
                "Test Name": test_name,
                "Rule": rule['rule'],
                "Relevant": rule['relevant'],
                "Reason": rule['reason']
            })
    # Convert to a DataFrame
    df = pd.DataFrame(csv_data)

    # Save the DataFrame to CSV format
    csv_file_path = csv_path
    df.to_csv(csv_file_path, index=False)


def evaluate_honeypot():
    # get all path in the directory
    caught_log_path = 'results/rule_generation/2024-10-28-13-33-57/splunk open source.csv'
    ground_truth_paths = 'dataset/honeypot ground truth'
    result = {'tp': [], 'fp': [], 'fn': [], 'ground_truth': []}
    caught_df = pd.read_csv(caught_log_path)
    ground_truths = os.listdir(ground_truth_paths)
    # sort the ground truth files by name
    ground_truths = sorted(ground_truths)
    # calculate the tp, fp, fn for every 5 ground truth files
    for i in range(0, len(ground_truths)):
        ground_truth = ground_truths[i]
        ground_truth_df = pd.read_csv(os.path.join(ground_truth_paths, ground_truth))
        # remove the 'Reason' or 'reason' column from the ground truth
        if 'Reason' in ground_truth_df.columns:
            ground_truth_df.drop('Reason', axis=1, inplace=True)
        elif 'reason' in ground_truth_df.columns:
            ground_truth_df.drop('reason', axis=1, inplace=True)
        ground_truth_df.to_csv(os.path.join(ground_truth_paths, ground_truth), index=False)
        # if the source is not in the ground truth, then it is a false positive
        fp = caught_df[~caught_df['source'].isin(ground_truth_df['source'])]
        # if the source is not in the caught log, then it is a false negative
        fn = ground_truth_df[~ground_truth_df['source'].isin(caught_df['source'])]
        # if the source is in both ground truth and caught log, then it is a true positive
        tp = ground_truth_df[ground_truth_df['source'].isin(caught_df['source'])]
        result['tp'].append(len(tp))
        result['fp'].append(len(fp))
        result['fn'].append(len(fn))
        result['ground_truth'].append(len(ground_truth_df))
    return result
