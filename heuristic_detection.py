def simple_heuristic(file_path):
    """
    A simple heuristic to detect potential malware based on file extension.
    This is just a basic example and not very effective. You should develop
    and implement more advanced heuristics for better detection.

    :param file_path: The path to the file to analyze.
    :return: True if the file is potentially malicious, False otherwise.
    """
    malicious_extensions = ['.exe', '.dll', '.vbs', '.js', '.bat']

    if any(file_path.endswith(extension) for extension in malicious_extensions):
        return True

    return False
