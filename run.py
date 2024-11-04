import os
import json
from src.ttp import analyse_ttp
from pprint import pprint
import logging
import time
from src.evaluate import evaluate_ttp, evaluate_rule_generation, evaluate_ttp_result, write_to_json_file, \
    rule_json_to_csv, generate_ttps, statistic_talos_ttps, evaluate_honeypot
from src.utils import extract_report_from_log

logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    handlers=[
                        logging.StreamHandler()  # 日志输出到控制台
                    ])


def run_streamlit():
    os.system('streamlit run src/app.py')


if __name__ == '__main__':
    run_streamlit()
