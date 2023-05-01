import os
import random

def create_test_file(file_path, infected):
    with open(file_path, 'w') as f:
        if infected:
            f.write('X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*')
        else:
            f.write('This is a clean test file.')

def main():
    test_files_dir = 'test_files'
    num_files = 6969
    infection_probability = 0.5  # Probability of a file being infected (0 to 1)
    malicious_extensions = ['.exe', '.dll', '.vbs', '.js', '.bat']

    if not os.path.exists(test_files_dir):
        os.makedirs(test_files_dir)

    for i in range(num_files):
        ext = random.choice(malicious_extensions)
        file_path = os.path.join(test_files_dir, f'test_file_{i}{ext}')
        infected = random.random() < infection_probability
        create_test_file(file_path, infected)

if __name__ == '__main__':
    main()
