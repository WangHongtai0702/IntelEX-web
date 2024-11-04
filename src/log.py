import re


class LogRecord:
    def __init__(self, logs_path: str):
        self.logs_path = logs_path
        self.atomic_test_list = []  # one log file  contain multiple atomic tests
        self.parse_atomic_test()

    def parse_atomic_test(self):
        with open(self.logs_path, "r", encoding="utf-8") as file:
            test_content = file.read()
        atomic_test_after_filter = test_content.split('Atomic Test Rules after filter:')
        if len(atomic_test_after_filter) == 2:
            atomic_test_after_filter = atomic_test_after_filter[1]
        else:
            atomic_test_after_filter = atomic_test_after_filter[0]
        atomic_test_content_list = atomic_test_after_filter.split('Atomic Test')
        atomic_test_content_list = [item for item in atomic_test_content_list if item.strip() != '']
        for atomic_test_content in atomic_test_content_list:
            self.atomic_test_list.append(AtomicTest(atomic_test_content))

    def __len__(self):
        return len(self.atomic_test_list)

    def display_info(self):
        for atomic_test in self.atomic_test_list:
            atomic_test.display_info()
            print('-' * 50)

    def get_atomic_test_by_number(self, test_number: str):
        for atomic_test in self.atomic_test_list:
            if atomic_test.get_test_number() == test_number:
                return atomic_test
        return None

    def get_log_by_process_id(self, process_id):
        for atomic_test in self.atomic_test_list:
            log = atomic_test.get_log_by_process_id(process_id)
            if log is not None:
                return log
        return None

    def calculate_confusion_matrix(self, ground_truth):
        true_positive = 0
        false_positive = 0
        false_negative = 0
        for atomic_test in self.atomic_test_list:
            atomic_test_number = atomic_test.get_test_number()
            ground_truth_atomic_test = ground_truth.get_atomic_test_by_number(atomic_test_number)
            if ground_truth_atomic_test is None:
                false_positive += len(atomic_test)
            else:
                for log in atomic_test.log_list:
                    process_id = log.process_id
                    ground_truth_log = ground_truth.get_log_by_process_id(process_id)
                    if ground_truth_log is None:
                        false_positive += 1
                    else:
                        true_positive += 1
                # tp, fp, fn = atomic_test.calculate_confusion_matrix(ground_truth_atomic_test)
                # true_positive += tp
                # false_positive += fp
                # false_negative += fn
        for atomic_test in ground_truth.atomic_test_list:
            atomic_test_number = atomic_test.get_test_number()
            if self.get_atomic_test_by_number(atomic_test_number) is None:
                false_negative += len(atomic_test)

        return {"true_positive": true_positive, "false_positive": false_positive, "false_negative": false_negative}


class AtomicTest:
    def __init__(self, test_content: str):
        self.test_content = test_content
        self.test_number = None
        self.test_name = None
        self.log_list = []  # one atomic test contain multiple logs
        self.parse_test()

    def parse_test(self):
        number_pattern = re.compile(r'#(1[0-5]|[1-9]\b)')
        atomic_test_index = re.search(number_pattern, self.test_content).group()
        self.test_number = atomic_test_index.strip()
        logs = re.findall(r"(Log\s?\d+.*?)(?=\n\n|$)", self.test_content, re.DOTALL)
        for i, log in enumerate(logs):
            self.log_list.append(Log(log))

    def get_test_number(self):
        return self.test_number

    def __len__(self):
        return len(self.log_list)

    def display_info(self):
        print(f"Atomic Test {self.test_number}:")
        for i, log in enumerate(self.log_list):
            print(f"Log {i + 1}:")
            log.display_info()

    def calculate_confusion_matrix(self, ground_truth):
        true_positive = 0
        false_positive = 0
        false_negative = 0
        for log in self.log_list:
            log_process_id = log.process_id
            ground_truth_log = ground_truth.get_log_by_process_id(log_process_id)
            if ground_truth_log is None:
                false_positive += 1
            else:
                true_positive += 1
        for log in ground_truth.log_list:
            process_id = log.process_id
            if self.get_log_by_process_id(process_id) is None:
                false_negative += 1
        return true_positive, false_positive, false_negative

    def get_log_by_process_id(self, process_id):
        for log in self.log_list:
            if log.process_id == process_id:
                return log
        return None


class Log:
    def __init__(self, log_content: str):
        self.log_content = log_content
        self.utc_time = None
        self.process_guid = None
        self.process_id = None
        self.command_line = None
        self.parse_log()  # 在初始化时自动解析日志

    def parse_log(self):
        self.utc_time = self.extract_value(r"UtcTime:\s*([^\n]+)")
        self.process_guid = self.extract_value(r"ProcessGuid:\s*([^\n]+)")
        self.process_id = self.extract_value(r"ProcessId:\s*([^\n]+)")
        self.command_line = self.extract_value(r"CommandLine:\s*([^\n]+)")

    def extract_value(self, pattern):
        match = re.search(pattern, self.log_content)
        return match.group(1) if match else None

    def display_info(self):
        print(f"UtcTime: {self.utc_time}")
        print(f"ProcessGuid: {self.process_guid}")
        print(f"ProcessId: {self.process_id}")
        print(f"CommandLine: {self.command_line}")
