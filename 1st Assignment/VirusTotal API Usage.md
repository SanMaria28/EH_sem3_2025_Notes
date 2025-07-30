# Assignment 13: VirusTotal API Usage


### Aim: 
Use VirusTotal's database to check if a file is malicious by analyzing its digital fingerprint

***Problem Statement:***

You're a security analyst who needs to quickly check if a suspicious file is safe or dangerous.

🔧 How: Get free API key from VirusTotal, write 10-15 lines of Python/bash code using curl to check file hash

----

### Methodology:
1. Create an API Key
   * Register for [VirusTotal](https://virustotal.com) API key.
   * Go to the Profile in the VirusTotal website and access the API Key.
     
     <img width="1918" height="422" alt="Screenshot 2025-07-30 225124" src="https://github.com/user-attachments/assets/cbf7c98f-42ca-44d2-8c57-6c408a3a1792" />
   * Copy the API Key.

2. Python Code to check file hash
   
```python
import hashlib
import requests

file_path = "D:/L&T FrontEnd UI UX/CSS Notes.txt"
with open(file_path, "rb") as f:
    file_hash = hashlib.sha256(f.read()).hexdigest()

api_key = "3b6e82c7650df8ee7de9c4723c26ce1670f715b1c8298c7d4a16c75cbff188b2"
response = requests.post(
    "https://www.virustotal.com/vtapi/v2/file/report",
    data={"apikey": api_key, "resource": file_hash}
)

print(response.json())
```

3. Upload the file to be scanned in VirusTotal Website

<img width="1000" height="800" alt="Screenshot 2025-07-30 230748" src="https://github.com/user-attachments/assets/801cc40f-292f-45eb-a937-cd3c802853ec" />

  * Click on *Choose File* option.
  * Choose the file you want to scan.

<img width="1900" height="800" alt="Screenshot 2025-07-30 230942" src="https://github.com/user-attachments/assets/1d6585b7-edfb-46ea-9a16-d801b82ef577" />

4. Run the Python Program
   * Make sure to provide the correct file path of the file that has been scanned in VirusTotal.
   * If it's present in the same directory as the python file, we could include the relative path, or else provide the absolute path.
   * For the API Key, copy and paste the API Key obtained from the Profile in VirusTotal website.

   ###### Output
<img width="900" height="261" alt="Screenshot 2025-07-30 231825" src="https://github.com/user-attachments/assets/3df41329-6b16-441a-b6c4-e7f10a2e6142" />
    
<img width="1950" height="1020" alt="Screenshot 2025-07-30 231909" src="https://github.com/user-attachments/assets/948455fe-4830-4f12-a138-f2a0ffcd124e" />

----

### Findings:
###### Analysis

- **API Key Usage**: The code uses a (redacted) API key as required.

- **File Hashing**: Uses Python’s hashlib to compute the SHA-256 hash, which is standard for VirusTotal.

- **API Call**: Uses requests.post to call the VirusTotal v2 API, sending the hash and the API key.

- **Prints Results**: The output JSON includes detection results from many antivirus engines.

The file’s hash is checked and VirusTotal’s multi-engine scan returns “detected: False” across all engines, suggesting the file is likely safe.

---
### Conclusion
***How Hash-Based Detection with VirusTotal Works***
* **Hashing**: Any file can be uniquely identified by its hash (commonly SHA-256). This is a digital fingerprint.
* **Database Lookup**: VirusTotal’s API allows you to query if a hash (file) is already known, and shows the verdict from >70 antivirus scanners.
  
This is a high-confidence and effective method for a security analyst to check a file’s safety using VirusTotal’s API.
  
