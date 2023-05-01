import os
import logging
import time
import threading

def setup_logging(log_file):
    logging.basicConfig(filename=log_file, level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def get_all_files(path):
    for root, _, files in os.walk(path):
        for file in files:
            yield os.path.join(root, file)

class ProgressReporter:
    def __init__(self, total_files):
        self.total_files = total_files
        self.scanned_files = 0
        self.lock = threading.Lock()

    def update(self):
        with self.lock:
            self.scanned_files += 1
            self.report_progress()

    def report_progress(self):
        progress_percentage = (self.scanned_files / self.total_files) * 100
        print(f"Scanned {self.scanned_files}/{self.total_files} files ({progress_percentage:.2f}%)")

def format_file_size(size_in_bytes):
    """
    Format a file size in bytes to a human-readable string.
    :param size_in_bytes: file size in bytes
    :return: human-readable file size string
    """
    for unit in ['', 'KB', 'MB', 'GB', 'TB']:
        if size_in_bytes < 1024.0:
            return f"{size_in_bytes:.1f} {unit}"
        size_in_bytes /= 1024.0
