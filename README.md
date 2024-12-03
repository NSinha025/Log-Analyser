# Log Analysis Script  

This project is a Python script designed for log analysis as part of VRV Security’s Python Intern Assignment. The script processes server log files to extract and analyze key information, including request counts per IP, the most frequently accessed endpoint, and detection of suspicious activity such as potential brute force login attempts.

---

## **Features**

1. **Count Requests per IP Address**  
   - Parses the log file to extract all IP addresses and calculates the number of requests made by each.  
   - Displays the results sorted in descending order of request counts.

2. **Identify the Most Frequently Accessed Endpoint**  
   - Extracts and identifies the endpoint accessed the highest number of times.  
   - Provides the endpoint name and its access count.

3. **Detect Suspicious Activity**  
   - Detects potential brute force login attempts by identifying IP addresses with failed login attempts exceeding a configurable threshold (default: 10).  

4. **Output Results**  
   - Displays results in the terminal in a clear and organized format.  
   - Saves the results to a CSV file (`log_analysis_results.csv`) with structured data for further review.

---

## **Getting Started**

### **Prerequisites**
- Python 3.x

### **Files Included**
- `main.py`: Python script for analyzing logs.  
- `sample.log`: Sample log file to test the script.
- `log_analysis_result.csv`: Output file generated.

### **Installation**
1. Clone or download the repository to your local machine.  
2. Ensure `sample.log` is in the same directory as the script.

---

## **Usage**

1. Run the script using Python:
   ```bash
   python log_analysis.py
   ```
2. The script will:  
   - Display the analysis results in the terminal.
   - Save the output to a CSV file (`log_analysis_results.csv`) in the same directory.

---

## **Output Format**

### **Terminal Output**
- **Requests per IP Address**  
   Displays IP addresses and the number of requests made, sorted by request count.  
   Example:  
   ```
   IP Address           Request Count
   192.168.1.1          234
   203.0.113.5          187
   ```

- **Most Frequently Accessed Endpoint**  
   Identifies the most accessed endpoint and its access count.  
   Example:  
   ```
   Most Frequently Accessed Endpoint:
   /home (Accessed 403 times)
   ```

- **Suspicious Activity Detected**  
   Lists IP addresses with failed login attempts exceeding the threshold.  
   Example:  
   ```
   Suspicious Activity Detected:
   IP Address           Failed Login Attempts
   192.168.1.100        56
   203.0.113.34         12
   ```

### **CSV Output**
The CSV file includes three sections:  
1. **Requests per IP**  
   - Columns: `IP Address`, `Request Count`
2. **Most Accessed Endpoint**  
   - Columns: `Endpoint`, `Access Count`
3. **Suspicious Activity**  
   - Columns: `IP Address`, `Failed Login Count`

---

## **Configuration**

To adjust the threshold for detecting suspicious activity, modify the constant in the script:  
```python
FAILED_LOGIN_THRESHOLD = 10
```

---
