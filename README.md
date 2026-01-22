# 👾 Pocket SOC V2.0: Cyberpunk Threat Hunter
> *A real-time Network Intrusion Detection System (IDS) wrapped in a professional Cyberpunk SOC interface.*

**Author:** Rutvik Sawant
**Tech Stack:** Python, Flask, Scapy, Pandas



---

## 🚀 New in V2.0
This tool has been upgraded from a simple "Flight Recorder" to a full **Security Operations Center (SOC)** dashboard.
* **🕵️ Entropy-Based Detection:** Uses mathematical entropy analysis to detect high-randomness domains (often used by malware for C2 communication).
* **🎨 Cyberpunk UI:** Custom CSS dashboard featuring neon-glow aesthetics, real-time threat tables, and a heads-up display (HUD).
* **⚡ Live Monitoring:** Tracks HTTP, TCP, UDP, and ICMP packets in real-time.

## 🛠️ Features
* **Smart Sniffer:** Captures network traffic and filters it instantly using `Scapy`.
* **Forensic Logging:** Automatically saves all traffic to a local `traffic_log.csv` (excluded from git for privacy).
* **Threat Logic:**
    * **Low Entropy:** Normal traffic (e.g., google.com) → `CLEAN`
    * **High Entropy:** Suspicious traffic (e.g., `xjkq-99-bot.net`) → `THREAT`

## 💻 Installation & Usage

1.  **Clone the repository:**
    ```bash
    git clone [https://github.com/RutvikSawant18/Python-IDS-Dashboard.git](https://github.com/RutvikSawant18/Python-IDS-Dashboard.git)
    cd Python-IDS-Dashboard
    ```

2.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

3.  **Run the Sniffer (Administrator/Root required):**
    ```bash
    # This captures the traffic in the background
    sudo python sniffer.py
    ```

4.  **Launch the Dashboard:**
    ```bash
    # Open a new terminal and run:
    python app.py
    ```
    *Open your browser and go to: `http://127.0.0.1:5000`*

---
*Educational Purpose Only. Do not use on networks you do not own.*
