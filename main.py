import os
import time
import argparse
import sys

from queue import Queue
from threading import Thread

from signature_detection import load_clamav_signature_database, scan_file_with_clamav
from heuristic_detection import simple_heuristic
from utils import format_file_size
def display_banner():
    banner = r"""
• ▌ ▄ ·.  ▄▄▄· ▄▄▌  ▄▄▌ ▐ ▄▌ ▄▄▄· ▄▄▄  ▄▄▄  ▪        ▄▄▄                                
·██ ▐███▪▐█ ▀█ ██•  ██· █▌▐█▐█ ▀█ ▀▄ █·▀▄ █·██ ▪     ▀▄ █·                              
▐█ ▌▐▌▐█·▄█▀▀█ ██▪  ██▪▐█▐▐▌▄█▀▀█ ▐▀▀▄ ▐▀▀▄ ▐█· ▄█▀▄ ▐▀▀▄                               
██ ██▌▐█▌▐█ ▪▐▌▐█▌▐▌▐█▌██▐█▌▐█ ▪▐▌▐█•█▌▐█•█▌▐█▌▐█▌.▐▌▐█•█▌                              
▀▀  █▪▀▀▀ ▀  ▀ .▀▀▀  ▀▀▀▀ ▀▪ ▀  ▀ .▀  ▀.▀  ▀▀▀▀ ▀█▄▀▪.▀  ▀                              
▄▄▄▄·  ▄· ▄▌    ·▄▄▄▄   ▄▄▄·  ▌ ▐·▪  ·▄▄▄▄      ▄▄▄        ·▄▄▄▄   ▄▄ • ▄▄▄ .▄▄▄  .▄▄ · 
▐█ ▀█▪▐█▪██▌    ██▪ ██ ▐█ ▀█ ▪█·█▌██ ██▪ ██     ▀▄ █·▪     ██▪ ██ ▐█ ▀ ▪▀▄.▀·▀▄ █·▐█ ▀. 
▐█▀▀█▄▐█▌▐█▪    ▐█· ▐█▌▄█▀▀█ ▐█▐█•▐█·▐█· ▐█▌    ▐▀▀▄  ▄█▀▄ ▐█· ▐█▌▄█ ▀█▄▐▀▀▪▄▐▀▀▄ ▄▀▀▀█▄
██▄▪▐█ ▐█▀·.    ██. ██ ▐█ ▪▐▌ ███ ▐█▌██. ██     ▐█•█▌▐█▌.▐▌██. ██ ▐█▄▪▐█▐█▄▄▌▐█•█▌▐█▄▪▐█
·▀▀▀▀   ▀ •     ▀▀▀▀▀•  ▀  ▀ . ▀  ▀▀▀▀▀▀▀▀•     .▀  ▀ ▀█▄▀▪▀▀▀▀▀• ·▀▀▀▀  ▀▀▀ .▀  ▀ ▀▀▀▀                                                                                                                               
    """
    print(banner)

# Call the function at the beginning of script
display_banner()


def main():
    while True:
        print("Malware Detection Tool")
        print("-----------------------")
        print("1. Start a scan")
        print("2. Exit")

        choice = input("Enter your choice (1/2): ")

        if choice == '1':
            dir_to_scan = input("Enter the directory to scan: ")
            exclude_dirs = input("Enter the comma-separated list of directories to exclude (leave blank if none): ")
            num_threads = int(input("Enter the number of threads to use for scanning: "))

            # Initialize ClamAV
            clamd = load_clamav_signature_database()

            # Initialize queue for file scanning
            file_queue = Queue()

            # Add files to the queue
            for root, dirs, files in os.walk(dir_to_scan):
                # Exclude directories if specified
                if exclude_dirs:
                    dirs[:] = [d for d in dirs if d not in exclude_dirs.split(',')]
                for file in files:
                    file_path = os.path.join(root, file)
                    file_queue.put(file_path)

            # Initialize result list
            results = []

            # Define worker function
            def worker(thread_id):
                while True:
                    file_path = file_queue.get()
                    if file_path is None:
                        break
                    try:
                        print(f"Thread-{thread_id} is scanning '{file_path}'")
                        # Scan file with ClamAV
                        clamav_result = scan_file_with_clamav(file_path, clamd)
                        # Scan file with heuristics
                        heuristic_result = simple_heuristic(file_path)
                        # Combine results
                        result = {
                            'file_path': file_path,
                            'clamav_result': clamav_result,
                            'heuristic_result': heuristic_result,
                        }
                        results.append(result)
                        file_queue.task_done()
                    except Exception as e:
                        print(f"Error scanning file '{file_path}': {e}")
                        file_queue.task_done()

            start_time = time.time()

            # Start worker threads
            for i in range(num_threads):
                t = Thread(target=worker, args=(i,))
                t.start()

            # Wait for all files to be scanned
            file_queue.join()

            end_time = time.time()
            elapsed_time = end_time - start_time

            # Print results
            detected_malware_files = []
            for result in results:
                file_size = os.path.getsize(result['file_path'])
                human_readable_file_size = format_file_size(file_size)
                print(f"{result['file_path']} ({human_readable_file_size})")
                print('  ClamAV: {}'.format(result['clamav_result']))
                print('  Heuristics: {}'.format(result['heuristic_result']))
                print()
                if result['clamav_result']:
                    print('WARNING: Malware detected!')
                    detected_malware_files.append(result['file_path'])
                print()

            if detected_malware_files:
                delete_choice = input("Do you want to delete detected malware files? (y/n): ")
                if delete_choice.lower() == 'y':
                    for file_path in detected_malware_files:
                        try:
                            os.remove(file_path)
                            print(f"Deleted '{file_path}'")
                        except Exception as e:
                            print(f"Error deleting file '{file_path}': {e}")

            print(f"Time taken to scan files: {elapsed_time:.2f} seconds")
            num_files_scanned = len(results)
            print(f"Number of files scanned: {num_files_scanned}")


        elif choice == '2':
            print("Exiting...")
            sys.exit()

        else:
            print("Invalid choice. Please try again.\n")

if __name__ == '__main__':
    main()
