# 🧠 Network Vulnerability Report Generator (Local Port Scanner)

This Python project scans the **open ports on your local IP**, identifies the associated **services**, and generates a detailed **PDF report** including possible **attacks** and recommended **precautions**, based on a pre-defined offline port vulnerability database.

---

## 📂 Project Structure

```
network-scanner/
├── main.py              # Main scanner & PDF generator script
├── port_vuln_db.py      # Contains known ports, attacks, and precautions
├── README.md            # This file
```

Ensure both `main.py` and `port_vuln_db.py` are in the **same directory**.

---

## ⚙️ Requirements

Install the required Python libraries using pip:

```bash
pip install python-nmap fpdf psutil
```

---

## 🚀 How to Use

1. **Clone the repository** or download the files.

2. Run the scanner:

```bash
python main.py
```

3. The script will:

   * Detect your **local IP**
   * Perform an **nmap version scan**
   * Look up **vulnerabilities** based on **port number**
   * Generate a PDF file: `YOUR_IP_network_report.pdf`

---

## 🛡️ Features

* ✅ Scans open ports using `nmap`
* ✅ Identifies service and version
* ✅ Matches port to known vulnerabilities
* ✅ Generates a structured PDF report with:

  * Open ports
  * Running services
  * Possible attacks
  * Suggested precautions

---

## 📘 Example Output

```
Port 22/tcp - Service: ssh, Version: OpenSSH 8.2
  -> Port 22 Risks: Brute force, user enumeration
  -> Port Precaution: Use key auth, disable root login

Port 5900/tcp - Service: vnc, Version: unknown
  -> Port 5900 Risks: Unauthenticated access, brute-force
  -> Port Precaution: Use strong passwords, restrict IPs
```

---

## 🤩 Extend It

To add more ports or update risks:

1. Open `port_vuln_db.py`
2. Add new entries in this format:

```python
1234: {
    "service": "MyService",
    "attack": "Sample attack vector",
    "precaution": "Recommended defense"
}
```

---

## 📌 Notes

* Ensure **`nmap`** is installed on your system.
* The script uses **offline port vulnerability data** for speed and privacy.
* Tested on **Python 3.8+**



---

## 👨‍💻 Author

Made with ❤️ by Siddharth Gaur
