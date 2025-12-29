from flask import Flask, render_template_string
import pandas as pd
import os

app = Flask(__name__)

LOG_FILE = "traffic_log.csv"
THREAT_LIST = ["example.com", "poker.com", "malware.test"]

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="refresh" content="5">
    <title>Network Sniffer Dashboard</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Courier New', monospace;
            background-color: #1a1a1a;
            color: #00ff00;
            padding: 20px;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
        }
        
        h1 {
            color: #00ff00;
            text-align: center;
            margin-bottom: 30px;
            font-size: 2.5em;
            text-shadow: 0 0 10px #00ff00;
        }
        
        .stats-box {
            background-color: #2a2a2a;
            border: 2px solid #00ff00;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 30px;
            display: flex;
            justify-content: space-around;
            box-shadow: 0 0 20px rgba(0, 255, 0, 0.3);
        }
        
        .stat-item {
            text-align: center;
        }
        
        .stat-label {
            color: #00ff00;
            font-size: 1.2em;
            margin-bottom: 10px;
            text-transform: uppercase;
        }
        
        .stat-value {
            color: #ffffff;
            font-size: 2em;
            font-weight: bold;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
            background-color: #2a2a2a;
            border: 2px solid #00ff00;
            box-shadow: 0 0 20px rgba(0, 255, 0, 0.3);
        }
        
        th {
            background-color: #00ff00;
            color: #1a1a1a;
            padding: 15px;
            text-align: left;
            font-size: 1.1em;
            text-transform: uppercase;
        }
        
        td {
            padding: 12px 15px;
            border-bottom: 1px solid #00ff00;
            color: #ffffff;
        }
        
        tr:hover {
            background-color: #3a3a3a;
        }
        
        tr.threat-row {
            background-color: #5c1818;
        }
        
        tr.threat-row:hover {
            background-color: #6c2828;
        }
        
        tr:last-child td {
            border-bottom: none;
        }
        
        .threat-label {
            color: #ff4444;
            font-weight: bold;
            margin-left: 10px;
        }
        
        .no-logs {
            text-align: center;
            color: #ff0000;
            font-size: 1.5em;
            margin-top: 50px;
        }
        
        .refresh-indicator {
            text-align: center;
            color: #888;
            margin-top: 20px;
            font-size: 0.9em;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>Network Sniffer Dashboard</h1>
        
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
        </div>
        
        <table>
            <thead>
                <tr>
                    <th>Timestamp</th>
                    <th>Source IP</th>
                    <th>Domain</th>
                </tr>
            </thead>
            <tbody>
                {% for row in data %}
                <tr {% if row['Domain'] in threat_list %}class="threat-row"{% endif %}>
                    <td>{{ row['Timestamp'] }}</td>
                    <td>{{ row['Source IP'] }}</td>
                    <td>{{ row['Domain'] }}{% if row['Domain'] in threat_list %} <span class="threat-label">⚠️ [THREAT DETECTED]</span>{% endif %}</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
        {% else %}
        <div class="no-logs">No logs found</div>
        {% endif %}
        
        <div class="refresh-indicator">Auto-refreshing every 5 seconds...</div>
    </div>
</body>
</html>
"""


@app.route('/')
def index():
    if not os.path.exists(LOG_FILE):
        return render_template_string(HTML_TEMPLATE, threat_list=THREAT_LIST)
    
    try:
        # Read CSV file
        df = pd.read_csv(LOG_FILE)
        
        # Sort by Timestamp (latest first) and take top 20 rows
        df['Timestamp'] = pd.to_datetime(df['Timestamp'])
        df_sorted = df.sort_values('Timestamp', ascending=False)
        top_20 = df_sorted.head(20)
        
        # Convert to list of dictionaries for template
        data = top_20.to_dict('records')
        
        # Calculate statistics
        total_count = len(df)
        unique_domains = df['Domain'].nunique()
        
        return render_template_string(HTML_TEMPLATE, 
                                    data=data, 
                                    total_count=total_count, 
                                    unique_domains=unique_domains,
                                    threat_list=THREAT_LIST)
    
    except Exception as e:
        return f"Error reading log file: {str(e)}", 500


if __name__ == '__main__':
    app.run(debug=True, port=5000)