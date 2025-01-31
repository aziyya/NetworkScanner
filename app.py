from flask import Flask, render_template_string, jsonify
import subprocess
import platform
import socket
from datetime import datetime

app = Flask(__name__)

def scan_wifi():
    if platform.system() != "Windows":
        return "This script only works on Windows systems."

    result = subprocess.run(["netsh", "wlan", "show", "networks", "mode=bssid"], capture_output=True, text=True)
    if result.returncode != 0:
        return "An error occurred while scanning for networks."

    wifi_networks = []
    ssid = None
    signal_strength = None
    mac_address = None
    security = None
    channel = None
    encryption = None

    for line in result.stdout.splitlines():
        if line.strip().startswith("SSID"):
            ssid = line.split(":")[1].strip()
        elif line.strip().startswith("Signal"):
            signal_strength = int(line.split(":")[1].strip().replace("%", ""))
        elif line.strip().startswith("BSSID"):
            mac_address = line.split(":")[1].strip()
        elif line.strip().startswith("Authentication"):
            auth_type = line.split(":")[1].strip()
            security, security_score = analyze_security(auth_type)
        elif line.strip().startswith("Encryption"):
            encryption = line.split(":")[1].strip()
        elif line.strip().startswith("Channel"):
            channel = line.split(":")[1].strip()

            if ssid and signal_strength is not None and mac_address and security and channel:
                wifi_networks.append({
                    'ssid': ssid,
                    'signal_strength': signal_strength,
                    'mac_address': mac_address,
                    'security': security,
                    'security_score': security_score,
                    'encryption': encryption,
                    'channel': channel,
                    'timestamp': datetime.now().strftime("%H:%M:%S")
                })
                ssid = None
                signal_strength = None
                mac_address = None
                security = None
                channel = None
                encryption = None

    if not wifi_networks:
        return "No networks found."

    wifi_networks.sort(key=lambda x: x['signal_strength'], reverse=True)
    return wifi_networks

def analyze_security(auth_type):
    security_levels = {
        "WPA3": ("Secure (WPA3)", 100),
        "WPA2": ("Moderate (WPA2)", 80),
        "WPA": ("Weak (WPA)", 40),
        "Open": ("Insecure (Open Network)", 0),
        "WEP": ("Insecure (WEP)", 10)
    }
    
    for key, (label, score) in security_levels.items():
        if key in auth_type:
            return label, score
    return "Unknown", 0

def get_ip_address():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0)
    try:
        s.connect(('10.254.254.254', 1))
        ip_address = s.getsockname()[0]
    except Exception:
        ip_address = '127.0.0.1'
    finally:
        s.close()
    return ip_address

@app.route('/')
def index():
    ip_address = get_ip_address()
    return render_template_string("""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Network Scanner</title>
        <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@300;400;500;600&display=swap" rel="stylesheet">
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        <style>
            * {
                margin: 0;
                padding: 0;
                box-sizing: border-box;
                font-family: 'Poppins', sans-serif;
            }

            body {
                background-color: #f8fafc;
                color: #1e3a8a;
            }

            .container {
                max-width: 1200px;
                margin: 2rem auto;
                padding: 0 1rem;
            }

            .header {
                text-align: center;
                margin-bottom: 2rem;
            }

            .header h1 {
                color: #1e3a8a;
                font-weight: 600;
            }

            .scan-button {
                background-color: #3b82f6;
                color: white;
                border: none;
                padding: 0.75rem 1.5rem;
                border-radius: 0.5rem;
                cursor: pointer;
                font-weight: 500;
                transition: background-color 0.2s;
            }

            .scan-button:hover {
                background-color: #2563eb;
            }

            .charts-container {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
                gap: 2rem;
                margin: 2rem 0;
            }

            .chart-card {
                background: white;
                border-radius: 1rem;
                padding: 1.5rem;
                box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
            }

            .network-grid {
                display: grid;
                gap: 1rem;
                margin-top: 2rem;
            }

            .network-card {
                background: white;
                border-radius: 0.75rem;
                padding: 1rem;
                box-shadow: 0 2px 4px rgba(0, 0, 0, 0.05);
            }

            .network-header {
                display: flex;
                justify-content: space-between;
                align-items: center;
                margin-bottom: 0.5rem;
            }

            .signal-meter {
                width: 100%;
                height: 6px;
                background: #e2e8f0;
                border-radius: 3px;
                overflow: hidden;
            }

            .signal-bar {
                height: 100%;
                background: #3b82f6;
                transition: width 0.3s ease;
            }

            .security-badge {
                padding: 0.25rem 0.75rem;
                border-radius: 1rem;
                font-size: 0.875rem;
                font-weight: 500;
            }

            .secure { background: #dcfce7; color: #166534; }
            .moderate { background: #fef9c3; color: #854d0e; }
            .weak { background: #fee2e2; color: #991b1b; }

            .network-details {
                display: flex;
                justify-content: space-between;
                font-size: 0.875rem;
                color: #64748b;
                margin-top: 0.5rem;
            }

            .refresh-icon {
                display: none;
            }

            @keyframes spin {
                to { transform: rotate(360deg); }
            }

            .refresh-icon.spinning {
                display: inline-block;
                animation: spin 1s linear infinite;
            }

 .overall-score {
                text-align: center;
                padding: 2rem;
                background: white;
                border-radius: 1rem;
                margin-bottom: 2rem;
                box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
            }

            .overall-score h2 {
                color: #1e3a8a;
                margin-bottom: 1rem;
            }

            .score-indicator {
                width: 100%;
                height: 8px;
                background: #e2e8f0;
                border-radius: 4px;
                margin: 1rem 0;
                overflow: hidden;
            }

            .score-fill {
                height: 100%;
                background: #3b82f6;
                transition: width 0.3s ease;
            }

            .metrics-grid {
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
                gap: 1rem;
                margin-bottom: 2rem;
            }

            .metric-card {
                background: white;
                padding: 1.5rem;
                border-radius: 1rem;
                box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
            }

            .metric-header {
                display: flex;
                align-items: center;
                gap: 0.75rem;
                margin-bottom: 1rem;
            }

            .metric-icon {
                font-size: 1.5rem;
                color: #3b82f6;
            }

            .vuln-list {
                background: white;
                border-radius: 1rem;
                padding: 1.5rem;
                margin: 2rem 0;
                box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
            }

            .vuln-item {
                display: flex;
                gap: 1rem;
                padding: 1rem;
                border-bottom: 1px solid #e2e8f0;
            }

            .vuln-badge {
                padding: 0.25rem 0.75rem;
                border-radius: 1rem;
                font-size: 0.875rem;
                font-weight: 500;
            }

            .critical { background: #fee2e2; color: #991b1b; }
            .high { background: #fef3c7; color: #92400e; }
            .medium { background: #f3f4f6; color: #1f2937; }

            .recommendations {
                background: white;
                border-radius: 1rem;
                padding: 1.5rem;
                margin: 2rem 0;
                box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1);
            }

            .rec-item {
                display: flex;
                gap: 1rem;
                padding: 1rem;
                border-bottom: 1px solid #e2e8f0;
            }

            .rec-icon {
                color: #3b82f6;
                font-size: 1.25rem;
            }

        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>Network Scanner</h1>
                <p>Local IP: {{ ip_address }}</p>
                <button id="scanBtn" class="scan-button">
                    <span class="refresh-icon">⟳</span>
                    Scan Networks
                </button>
            </div>

            <div class="charts-container">
                <div class="chart-card">
                    <h3>Signal Strength</h3>
                    <canvas id="signalChart"></canvas>
                </div>
                <div class="chart-card">
                    <h3>Security Distribution</h3>
                    <canvas id="securityChart"></canvas>
                </div>
            </div>

            <div class="vuln-list">
                <h2>Current Vulnerabilities</h2>
                <div class="vuln-item">
                    <span class="vuln-badge critical">Critical</span>
                    <div>
                        <h4>WEP Encryption Detected</h4>
                        <p>Outdated encryption method vulnerable to attacks</p>
                    </div>
                </div>
                <div class="vuln-item">
                    <span class="vuln-badge high">High</span>
                    <div>
                        <h4>Weak Password Policy</h4>
                        <p>Network passwords don't meet security requirements</p>
                    </div>
                </div>
                <div class="vuln-item">
                    <span class="vuln-badge medium">Medium</span>
                    <div>
                        <h4>Guest Network Exposure</h4>
                        <p>Guest network has access to internal resources</p>
                    </div>
                </div>
            </div>

            <div class="recommendations">
                <h2>Security Recommendations</h2>
                <div class="rec-item">
                    <span class="rec-icon">⚠️</span>
                    <div>
                        <h4>Update Network Encryption</h4>
                        <p>Upgrade to WPA3 encryption for enhanced security</p>
                    </div>
                </div>
                <div class="rec-item">
                    <span class="rec-icon">⚡</span>
                    <div>
                        <h4>Enable MAC Filtering</h4>
                        <p>Implement MAC address filtering for better access control</p>
                    </div>
                </div>
                <div class="rec-item">
                    <span class="rec-icon">🔄</span>
                    <div>
                        <h4>Regular Security Audits</h4>
                        <p>Schedule weekly security scans and reviews</p>
                    </div>
                </div>
            </div>

            <div id="networkGrid" class="network-grid"></div>
        </div>

        <script>
            let signalChart, securityChart;

            function initCharts() {
                const signalCtx = document.getElementById('signalChart').getContext('2d');
                const securityCtx = document.getElementById('securityChart').getContext('2d');

                signalChart = new Chart(signalCtx, {
                    type: 'bar',
                    data: {
                        labels: [],
                        datasets: [{
                            label: 'Signal Strength (%)',
                            data: [],
                            backgroundColor: '#3b82f6',
                            borderRadius: 4
                        }]
                    },
                    options: {
                        responsive: true,
                        plugins: {
                            legend: { display: false }
                        },
                        scales: {
                            y: {
                                beginAtZero: true,
                                max: 100
                            }
                        }
                    }
                });

                securityChart = new Chart(securityCtx, {
                    type: 'doughnut',
                    data: {
                        labels: ['Secure', 'Moderate', 'Weak', 'Insecure'],
                        datasets: [{
                            data: [0, 0, 0, 0],
                            backgroundColor: ['#22c55e', '#eab308', '#ef4444', '#64748b']
                        }]
                    },
                    options: {
                        responsive: true,
                        plugins: {
                            legend: { position: 'right' }
                        }
                    }
                });
            }

            function updateNetworks(networks) {
                const grid = document.getElementById('networkGrid');
                grid.innerHTML = '';

                networks.forEach(network => {
                    const card = document.createElement('div');
                    card.className = 'network-card';
                    
                    const securityClass = network.security.toLowerCase().includes('secure') ? 'secure' :
                                        network.security.toLowerCase().includes('moderate') ? 'moderate' : 'weak';

                    card.innerHTML = `
                        <div class="network-header">
                            <h3>${network.ssid}</h3>
                            <span class="security-badge ${securityClass}">${network.security}</span>
                        </div>
                        <div class="signal-meter">
                            <div class="signal-bar" style="width: ${network.signal_strength}%"></div>
                        </div>
                        <div class="network-details">
                            <span>Signal: ${network.signal_strength}%</span>
                            <span>Channel: ${network.channel}</span>
                            <span>MAC: ${network.mac_address}</span>
                        </div>
                    `;
                    grid.appendChild(card);
                });

                // Update charts
                signalChart.data.labels = networks.map(n => n.ssid);
                signalChart.data.datasets[0].data = networks.map(n => n.signal_strength);
                signalChart.update();

                const securityCounts = [0, 0, 0, 0];
                networks.forEach(n => {
                    if (n.security.includes('Secure')) securityCounts[0]++;
                    else if (n.security.includes('Moderate')) securityCounts[1]++;
                    else if (n.security.includes('Weak')) securityCounts[2]++;
                    else securityCounts[3]++;
                });
                securityChart.data.datasets[0].data = securityCounts;
                securityChart.update();
            }

            document.addEventListener('DOMContentLoaded', () => {
                initCharts();
                
                document.getElementById('scanBtn').addEventListener('click', function() {
                    const icon = this.querySelector('.refresh-icon');
                    icon.classList.add('spinning');
                    
                    fetch('/scan_wifi')
                        .then(response => response.json())
                        .then(data => {
                            if (Array.isArray(data)) {
                                updateNetworks(data);
                            }
                        })
                        .catch(error => console.error('Error:', error))
                        .finally(() => {
                            icon.classList.remove('spinning');
                        });
                });
            });
        </script>
    </body>
    </html>
    """, ip_address=ip_address)

@app.route('/scan_wifi')
def scan_wifi_route():
    wifi_networks = scan_wifi()
    if isinstance(wifi_networks, str):
        return jsonify({"error": wifi_networks})
    return jsonify(wifi_networks)

if __name__ == '__main__':
    app.run(debug=True)