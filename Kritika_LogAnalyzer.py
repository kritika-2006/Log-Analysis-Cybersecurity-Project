import re
from collections import Counter

def analyze_logs(log_file_path, threshold=3):
    failed_attempts = []
    
    # Simple regex to find IP addresses and failed login messages in logs
    ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    
    print("[*] Analyzing server log file for suspicious activities...\n")
    
    try:
        with open(log_file_path, 'r') as file:
            for line in file:
                if "FAILED LOGIN" in line or "Invalid password" in line:
                    match = re.search(ip_pattern, line)
                    if match:
                        failed_attempts.append(match.group())
                        
        # Count failures per IP
        ip_counts = Counter(failed_attempts)
        
        print("--- Security Analysis Report ---")
        suspicious_found = False
        for ip, count in ip_counts.items():
            if count >= threshold:
                print(f"[!] ALERT: Potential Brute-Force Attack detected from IP: {ip} ({count} failed attempts)")
                suspicious_found = True
                
        if not suspicious_found:
            print("[+] No suspicious brute-force activity detected.")
            
    except FileNotFoundError:
        print(f"[!] Error: The file {log_file_path} was not found.")

# Sample test execution
if __name__ == "__main__":
    # Creating a dummy log file for testing purpose
    sample_log_data = """
    192.168.1.10 - - [27/Oct/2026:10:00:01] "POST /login" SUCCESS
    192.168.1.50 - - [27/Oct/2026:10:05:12] "POST /login" FAILED LOGIN
    192.168.1.50 - - [27/Oct/2026:10:05:15] "POST /login" FAILED LOGIN
    192.168.1.50 - - [27/Oct/2026:10:05:18] "POST /login" FAILED LOGIN
    192.168.1.20 - - [27/Oct/2026:10:10:00] "POST /login" SUCCESS
    """
    
    with open("server_access.log", "w") as f:
        f.write(sample_log_data.strip())
        
    # Run the analyzer on the sample log
    analyze_logs("server_access.log", threshold=3)