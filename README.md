# FilterMapIR 🌐

[![Daily Scan](https://github.com/tawanamohammadi/FilterMapIR/actions/workflows/daily-scan.yml/badge.svg)](https://github.com/tawanamohammadi/FilterMapIR/actions/workflows/daily-scan.yml)
![Last Updated](https://img.shields.io/badge/dynamic/json?url=https://tawanamohammadi.github.io/FilterMapIR/data/history.json&query=$[0].date&label=Last%20Scan&color=00d4aa)
![License](https://img.shields.io/badge/License-MIT-blue.svg)

**Daily Iran Firewall/Reachability Scanner** - اسکنر روزانه دسترسی اینترنت ایران

A comprehensive system for monitoring and mapping internet reachability in Iran. This project automatically tests connectivity to various online services and generates detailed reports.

## 🚀 Features

- **Automated Daily Scans**: GitHub Actions runs network tests automatically every day
- **Comprehensive Testing**: DNS resolution, ICMP ping, TCP port checks, TLS/HTTPS verification
- **Professional Dashboard**: Real-time visualization of scan results on GitHub Pages
- **Historical Data**: Track trends over time with historical reports
- **Export Formats**: JSON, CSV, and Markdown reports for each scan

## 📊 Live Dashboard

Visit the live dashboard: **[tawanamohammadi.github.io/FilterMapIR](https://tawanamohammadi.github.io/FilterMapIR)**

## 🏗️ Project Structure

```
FilterMapIR/
├── .github/
│   └── workflows/
│       └── daily-scan.yml      # GitHub Actions workflow
├── scripts/
│   └── netcheck.ps1            # Main network testing script
├── targets/
│   └── targets.json            # Target definitions
├── reports/
│   └── YYYY-MM-DD/             # Daily report directories
│       ├── summary.json
│       ├── summary.csv
│       ├── summary.md
│       └── raw/                # Raw test outputs
├── docs/                       # GitHub Pages site
│   ├── index.html              # Dashboard
│   ├── history.html            # Historical view
│   └── data/                   # Data for the site
└── README.md
```

## 🛠️ How It Works

### Network Tests

For each target, the scanner performs:

1. **DNS Resolution** - Resolves A and AAAA records
2. **ICMP Ping** - Tests basic connectivity with configurable packet count
3. **Traceroute** - Optional path analysis (can be enabled/disabled)
4. **TCP Port Check** - Tests each specified port using Test-NetConnection
5. **TLS/HTTPS** - For port 443, performs curl to check TLS handshake

### Status Classifications

| Status | Description |
|--------|-------------|
| ✅ PASS | All tests successful |
| ⚡ PARTIAL | Some ports blocked |
| ⚠️ DEGRADED | High latency or packet loss |
| 🚫 BLOCKED | No connectivity |
| ❌ DNS_FAIL | DNS resolution failed |

## 🏃 Running Locally

### Prerequisites

- Windows 10/11 or Windows Server
- PowerShell 5.1 or later
- curl (included in Windows 10+)

### Run a Manual Scan

```powershell
# Clone the repository
git clone https://github.com/tawanamohammadi/FilterMapIR.git
cd FilterMapIR

# Run the scanner
.\scripts\netcheck.ps1

# With traceroute enabled
.\scripts\netcheck.ps1 -EnableTraceroute

# Custom targets file
.\scripts\netcheck.ps1 -TargetsFile .\targets\custom-targets.json
```

### Configuration Options

The `targets.json` file supports:

```json
{
  "settings": {
    "pingCount": 4,           // Number of ICMP packets
    "timeoutSeconds": 10,     // Timeout for each test
    "enableTraceroute": false, // Enable/disable traceroute
    "maxTracerouteHops": 15    // Maximum hops for traceroute
  },
  "targets": [
    {
      "name": "Example",
      "host": "example.com",
      "ports": [80, 443],
      "category": "Web",
      "priority": "high",
      "note": "Example website"
    }
  ]
}
```

## ➕ Adding New Targets

1. Edit `targets/targets.json`
2. Add a new entry to the `targets` array:

```json
{
  "name": "New Service",
  "host": "service.example.com",
  "ports": [443],
  "category": "CategoryName",
  "priority": "high|medium|low",
  "note": "Description of the service"
}
```

3. Commit and push your changes

## 🌐 Enabling GitHub Pages

1. Go to your repository **Settings**
2. Navigate to **Pages** in the sidebar
3. Under **Source**, select **Deploy from a branch**
4. Set **Branch** to `main` and folder to `/docs`
5. Click **Save**
6. Wait a few minutes for deployment
7. Your dashboard will be available at `https://yourusername.github.io/FilterMapIR`

## 📅 Scheduled Runs

The GitHub Actions workflow runs:
- Automatically at **00:00 UTC** daily (~03:30 Iran time)
- Manually via **workflow_dispatch** (go to Actions → Daily Scan → Run workflow)

## 🔒 Privacy Notice

- This project tests **publicly accessible** services only
- No authentication credentials are stored or used
- All scan results are public on GitHub Pages
- IP addresses of scan targets are visible in reports
- This tool is for **research and monitoring purposes** only

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## ⚠️ Disclaimer

This tool is provided for educational and research purposes. Users are responsible for ensuring their use of this tool complies with applicable laws and regulations. The maintainers do not endorse using this tool to circumvent any restrictions.

---

Made with ❤️ by the FilterMapIR Team
