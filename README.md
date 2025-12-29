\# 🛡️ Network Flight Recorder (NFR) \& IDS Dashboard



A custom-built Network Intrusion Detection System (IDS) and traffic analyzer. This tool captures network packets in real-time, logs them for forensic analysis, and visualizes the data via a web-based dashboard.



\*\*Author:\*\* Rutvik Sawant  

\*\*Tech Stack:\*\* Python, Flask, Scapy, Pandas



---



\## 🚀 Features

\* \*\*Packet Sniffer:\*\* Captures HTTP, TCP, UDP, and ICMP traffic in real-time using `Scapy`.

\* \*\*Live Dashboard:\*\* Web interface built with `Flask` to visualize traffic patterns.

\* \*\*Forensic Logging:\*\* Automatically saves captured packet data to `traffic\_log.csv` for analysis.

\* \*\*Threat Detection:\*\* Basic signature matching for suspicious IPs and protocols.



---



\## 🛠️ Installation



1\.  \*\*Clone the repository:\*\*

&nbsp;   ```bash

&nbsp;   git clone \[https://github.com/RutvikSawant18/Python-IDS-Dashboard.git](https://github.com/RutvikSawant18/Python-IDS-Dashboard.git)

&nbsp;   cd Python-IDS-Dashboard

&nbsp;   ```



2\.  \*\*Install dependencies:\*\*

&nbsp;   ```bash

&nbsp;   pip install -r requirements.txt

&nbsp;   ```



---



\## 💻 Usage



\### Step 1: Start the Sniffer

(Must run as Administrator/Root to capture packets)

```bash

python sniffer.py

