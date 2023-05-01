import pyclamd

def load_clamav_signature_database():
    """
    Load ClamAV signature database.
    """
    clamd = pyclamd.ClamdNetworkSocket()

    return clamd

def scan_file_with_clamav(file_path, clamd):
    """
    Scan a file with ClamAV.
    
    :param file_path: The path to the file to scan.
    :param clamd: The ClamAV instance.
    :return: Scan result.
    """
    try:
        scan_result = clamd.scan_file(file_path)  # Change 'scan' to 'scan_file'
        if scan_result is None:
            return None
        else:
            return scan_result[file_path][1]
    except Exception as e:
        print(f"Error scanning file with ClamAV: {e}")
        return None
