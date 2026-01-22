from flask import Flask, render_template_string
import pandas as pd
import os

app = Flask(__name__)

LOG_FILE = "traffic_log.csv"

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="refresh" content="5">
    <title>Pocket SOC v2.0 — DNS Threat Dashboard</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: 'JetBrains Mono', 'Fira Mono', 'Courier New', monospace;
            background: linear-gradient(120deg, #1a0033, #061421, #0f0026 85%);
            color: #39ff14;
            padding: 24px;
            min-height: 100vh;
        }
        .container {
            max-width: 1300px;
            margin: 0 auto;
        }
        h1 {
            color: #39ff14;
            text-align: center;
            margin-bottom: 28px;
            font-size: 3em;
            text-shadow: 0 0 16px #00ffea, 0 0 1px #fff;
            font-family: 'Orbitron', 'JetBrains Mono', monospace;
            letter-spacing: 0.08em;
        }
        .v2-label {
            display: inline-block;
            background: linear-gradient(90deg, #ff0055 0%, #f5a623 100%);
            color: #fff;
            border-radius: 6px;
            font-size: 0.75em;
            font-weight: bold;
            margin-left: 12px;
            padding: 0.2em 0.9em;
            letter-spacing: 0.11em;
            box-shadow: 0 0 12px #ff0055;
            vertical-align: middle;
            text-shadow: 0 0 2px #000;
        }
        .stats-box {
            background: rgba(10,10,18,0.96);
            border: 2px solid #39ff14;
            border-radius: 10px;
            margin-bottom: 35px;
            display: flex;
            justify-content: space-evenly;
            align-items: center;
            box-shadow: 0 0 32px #39ff1433, 0 0 10px #0f0d2a66;
            padding: 28px 0 18px 0;
        }
        .stat-item {
            text-align: center;
            margin: 0 10px;
            flex: 1 1 0;
        }
        .stat-label {
            color: #39ff14;
            font-size: 1em;
            margin-bottom: 8px;
            font-weight: bold;
            text-transform: uppercase;
            letter-spacing: .09em;
        }
        .stat-value {
            color: #fff;
            font-size: 2.4em;
            font-weight: bolder;
            text-shadow: 0 0 4px #00ff42, 0 0 2px #fff;
            margin-bottom: 0.2em;
        }
        .stat-value.threats {
            color: #ff0055;
            text-shadow: 0 0 18px #ff0055, 0 0 2px #bf002e;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            border: 2.5px solid #39ff14;
            background: linear-gradient(110deg, #0f0e1b 80%, #23253a 100%);
            box-shadow: 0 0 18px 2px #39ff1440, 0 0 6px #5fa31980 inset;
            margin-bottom: 18px;
        }
        th {
            background: linear-gradient(90deg, #161616 80%, #262e28 100%);
            color: #00fff0;
            padding: 17px 18px;
            font-size: 1.15em;
            border-bottom: 2px solid #39ff14;
            letter-spacing: .12em;
            text-shadow: 0 0 6px #00ffea70;
        }
        td {
            padding: 13px 18px;
            border-bottom: 1px solid #1bff7550;
            color: #fff;
            font-family: inherit;
            font-size: 1.09em;
        }
        tr:hover {
            background: #242447;
        }
        .badge {
            display: inline-block;
            font-weight: bold;
            padding: 0.27em 0.95em;
            border-radius: 16px;
            font-size: 1em;
            letter-spacing: .10em;
            text-shadow: 0 0 3px #111;
            border: 1.5px solid #222;
        }
        .badge-malicious {
            background: linear-gradient(90deg, #3a0014 40%, #90001b 100%);
            color: #ff0055;
            border: 1.5px solid #ff0055;
            box-shadow: 0 0 8px #ff456644;
            text-shadow: 0 0 2px #ffe3e3;
        }
        .badge-high {
            background: linear-gradient(90deg, #443200 40%, #a54103 100%);
            color: #ffe600;
            border: 1.5px solid #ffa600;
            box-shadow: 0 0 7px #ffe45a70;
            text-shadow: 0 0 1px #fff1be;
        }
        .badge-suspicious {
            background: linear-gradient(90deg, #3a2900 40%, #9d5600 100%);
            color: #ff9900;
            border: 1.5px solid #ff9900;
            box-shadow: 0 0 7px #ff980080;
        }
        .badge-clean {
            background: linear-gradient(90deg, #004429 20%, #025c35 90%);
            color: #43ffe6;
            border: 1.5px solid #09ffa5;
            box-shadow: 0 0 6px #39ffd244;
            text-shadow: 0 0 2px #c1fff0;
        }
        .no-logs {
            text-align: center;
            color: #ff0055;
            font-size: 1.4em;
            margin: 44px auto 0 auto;
            letter-spacing: 0.08em;
        }
        .refresh-indicator {
            text-align: center;
            color: #26ffa9;
            margin-top: 18px;
            font-size: 1em;
            letter-spacing: .09em;
            text-shadow: 0 0 2px #27ff7e88;
        }
        @media (max-width: 850px) {
            .stats-box { flex-direction: column; gap: 15px; }
            th, td { font-size: 0.93em; padding: 8px 7px; }
        }
        @media (max-width: 600px) {
            h1 { font-size: 1.3em; }
            th, td { font-size: 0.80em; }
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>
            Pocket SOC <span class="v2-label">DASHBOARD V2.0</span>
        </h1>
        
        {% if data is defined and data|length > 0 %}
        <div class="stats-box">
            <div class="stat-item">
                <div class="stat-label">Total Requests</div>
                <div class="stat-value">{{ total_count }}</div>
            </div>
            <div class="stat-item">
                <div class="stat-label">Unique Domains</div>
                <div class="stat-value">{{ unique_domains }}</div>
            </div>
            <div class="stat-item">
                <div class="stat-label">Threats Detected</div>
                <div class="stat-value threats">{{ threat_count }}</div>
            </div>
        </div>
        <table>
            <thead>
                <tr>
                    <th>Timestamp</th>
                    <th>Source IP</th>
                    <th>Domain</th>
                    <th>Status</th>
                    <th>Entropy Score</th>
                </tr>
            </thead>
            <tbody>
                {% for row in data %}
                <tr>
                    <td>{{ row['Timestamp'] }}</td>
                    <td>{{ row['Source IP'] }}</td>
                    <td>{{ row['Domain'] }}</td>
                    <td>
                        {% set status = row['Status']|upper %}
                        {% if "MALICIOUS" in status %}
                            <span class="badge badge-malicious">{{ row['Status'] }}</span>
                        {% elif "HIGH" in status %}
                            <span class="badge badge-high">{{ row['Status'] }}</span>
                        {% elif "SUSPICIOUS" in status %}
                            <span class="badge badge-suspicious">{{ row['Status'] }}</span>
                        {% elif "CLEAN" in status %}
                            <span class="badge badge-clean">{{ row['Status'] }}</span>
                        {% else %}
                            <span class="badge">{{ row['Status'] }}</span>
                        {% endif %}
                    </td>
                    <td>
                        {% if row['Risk Score'] != "" %}
                            {{ ("%0.2f"|format(row['Risk Score']|float)) }}
                        {% else %}
                            N/A
                        {% endif %}
                    </td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
        {% else %}
        <div class="no-logs">No logs found</div>
        {% endif %}
        
        <div class="refresh-indicator">
            ⚡ Data auto-refreshes every 5 seconds
        </div>
    </div>
</body>
</html>
"""

@app.route('/')
def index():
    if not os.path.exists(LOG_FILE):
        return render_template_string(HTML_TEMPLATE)
    try:
        # Expect these columns: Timestamp, Source IP, Domain, Status, Risk Score
        df = pd.read_csv(LOG_FILE)

        # Ensure columns are present and use only the needed ones
        expected_cols = ["Timestamp", "Source IP", "Domain", "Status", "Risk Score"]
        for col in expected_cols:
            if col not in df.columns:
                return f"<b>Error:</b> Log missing column '{col}'.", 500
        df = df[expected_cols]

        # Sort, take top 20, convert Risk Score to float if possible
        df['Timestamp'] = pd.to_datetime(df['Timestamp'], errors='coerce')
        df_sorted = df.sort_values('Timestamp', ascending=False)
        top_20 = df_sorted.head(20)
        # Convert risk score to float where possible (for formatting/rounding in Jinja)
        top_20['Risk Score'] = pd.to_numeric(top_20['Risk Score'], errors='coerce').fillna("")

        data = top_20.to_dict('records')
        total_count = len(df)
        unique_domains = df['Domain'].nunique()
        threat_count = df['Status'].fillna('').str.upper().str.contains('MALICIOUS|HIGH', na=False).sum()

        return render_template_string(
            HTML_TEMPLATE,
            data=data,
            total_count=total_count,
            unique_domains=unique_domains,
            threat_count=threat_count
        )
    except Exception as e:
        return f"Error reading log file: {str(e)}", 500

if __name__ == '__main__':
    app.run(debug=True, port=5000, host='0.0.0.0')