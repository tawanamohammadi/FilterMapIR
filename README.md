# FilterMapIR 🛡️

<div align="center">

[![Daily Scan](https://github.com/tawanamohammadi/FilterMapIR/actions/workflows/daily-scan.yml/badge.svg)](https://github.com/tawanamohammadi/FilterMapIR/actions/workflows/daily-scan.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![GitHub Pages](https://img.shields.io/badge/Dashboard-Live-00d4aa)](https://tawanamohammadi.github.io/FilterMapIR/)

**Advanced Network Intelligence & Reachability Scanner**

*Professional-grade network monitoring with ASN tracking, TLS analysis, and routing intelligence*

[🌐 Live Dashboard](https://tawanamohammadi.github.io/FilterMapIR/) • [📊 Latest Report](https://github.com/tawanamohammadi/FilterMapIR/tree/main/reports) • [📖 Documentation](#-how-it-works)

</div>

---

## 🎯 Overview

FilterMapIR is a comprehensive network intelligence system that performs multi-layer network analysis. It automatically tests connectivity to various online services, gathers detailed network intelligence, and generates professional reports with visualizations.

### Key Features

| Feature | Description |
|---------|-------------|
| 🔍 **Multi-Layer Analysis** | DNS, ICMP, TCP, TLS/SSL testing across all network layers |
| 🌍 **ASN Intelligence** | Automatic ASN detection and geolocation for all targets |
| 📊 **Jitter Analysis** | Latency variance and standard deviation calculation |
| 🔀 **Route Mapping** | Traceroute with ASN mapping for each hop |
| 🔐 **TLS Inspection** | Certificate analysis, version detection, expiry tracking |
| 🛡️ **Privacy First** | Scanner location anonymized (only country/ISP shown) |
| 📈 **Trend Tracking** | Historical data with visual charts |
| 🤖 **Fully Automated** | GitHub Actions runs scans twice daily |

---

## 📊 Live Dashboard

Visit the interactive dashboard: **[tawanamohammadi.github.io/FilterMapIR](https://tawanamohammadi.github.io/FilterMapIR/)**

The dashboard provides:
- Real-time scan status with scanner location info
- Target intelligence (Country, ASN, ISP)
- Pass/Fail statistics with trend charts
- Filterable results table
- Category breakdown
- Historical reports

---

## 🏗️ Project Structure

```
FilterMapIR/
├── 📁 .github/workflows/
│   └── daily-scan.yml          # GitHub Actions workflow
├── 📁 scripts/
│   └── netcheck.ps1            # Advanced network scanner
├── 📁 targets/
│   └── targets.json            # Target definitions
├── 📁 reports/
│   ├── latest.json             # Pointer to latest report
│   └── YYYY-MM-DD/             # Daily reports
│       ├── summary.json        # Full scan results
│       ├── summary.csv         # CSV export
│       ├── summary.md          # Markdown report
│       └── metadata.json       # Run metadata
├── 📁 docs/                    # GitHub Pages dashboard
│   ├── index.html              # Main dashboard
│   ├── history.html            # Historical view
│   └── data/                   # Dashboard data
├── README.md
└── LICENSE
```

---

## 🛠️ How It Works

### Network Tests Performed

For each target, the scanner performs comprehensive multi-layer analysis:

#### Layer 3 - Network
| Test | Description | Metrics |
|------|-------------|---------|
| DNS Resolution | A/AAAA record lookup | Resolution time, CNAME chain, DNS provider |
| ICMP Ping | Connectivity test | Min/Max/Avg latency, Jitter, Packet loss |
| Traceroute | Route analysis | Hop count, Transit ASNs, Countries |

#### Layer 4 - Transport
| Test | Description | Metrics |
|------|-------------|---------|
| TCP Port Scan | Port connectivity | State (Open/Filtered), Response time |
| Service Detection | Common port identification | Service name mapping |

#### Layer 7 - Application
| Test | Description | Metrics |
|------|-------------|---------|
| TLS/HTTPS | Secure connection | TLS version, Cipher, Certificate validity |
| Certificate | X.509 analysis | Issuer, Expiry, SAN, Wildcard status |
| HTTP Headers | Server fingerprinting | Server software, CDN detection |

### Intelligence Gathering

For each target IP, the scanner collects:
- **Geolocation**: Country, City
- **Network**: ASN, ASN Name, ISP
- **Classification**: CDN detection, Datacenter vs Residential
- **Routing**: Transit ASNs, Country hops

### Status Classifications

| Status | Icon | Meaning |
|--------|------|---------|
| PASS | ✅ | All tests successful |
| PARTIAL | ⚡ | Some ports blocked or high packet loss |
| DEGRADED | ⚠️ | High latency (>300ms) or jitter |
| BLOCKED | 🚫 | No connectivity, TCP filtered |
| DNS_FAIL | ❌ | DNS resolution failed |

---

## 🚀 Quick Start

### Prerequisites

- Windows 10/11 or Windows Server 2016+
- PowerShell 5.1 or later
- curl (included in Windows 10+)

### Run a Manual Scan

```powershell
# Clone the repository
git clone https://github.com/tawanamohammadi/FilterMapIR.git
cd FilterMapIR

# Run basic scan
.\scripts\netcheck.ps1

# Run with traceroute enabled
.\scripts\netcheck.ps1 -EnableTraceroute

# Run deep scan mode
.\scripts\netcheck.ps1 -DeepScan

# Use custom targets file
.\scripts\netcheck.ps1 -TargetsFile .\targets\custom.json
```

### Script Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `-TargetsFile` | String | Path to targets JSON file |
| `-OutputDir` | String | Output directory for reports |
| `-EnableTraceroute` | Switch | Enable route analysis |
| `-DisableTraceroute` | Switch | Force disable traceroute |
| `-DeepScan` | Switch | More comprehensive testing |

---

## ⚙️ Configuration

### targets.json Structure

```json
{
  "metadata": {
    "version": "1.0.0",
    "description": "FilterMapIR Targets"
  },
  "settings": {
    "pingCount": 10,           // ICMP packets per target
    "timeoutSeconds": 10,      // Timeout for each test
    "enableTraceroute": false, // Default traceroute setting
    "maxTracerouteHops": 20    // Max hops for traceroute
  },
  "targets": [
    {
      "name": "Service Name",
      "host": "example.com",
      "ports": [80, 443],
      "category": "Category",
      "priority": "high",
      "note": "Description"
    }
  ]
}
```

### Adding New Targets

1. Edit `targets/targets.json`
2. Add entry to the `targets` array
3. Commit and push

---

## 🔄 GitHub Actions Workflow

### Features

- **Dual Daily Scans**: Runs at 00:00 and 12:00 UTC
- **Manual Trigger**: Start scan anytime with options
- **Deep Scan Mode**: Optional comprehensive testing
- **Traceroute Toggle**: Enable/disable route analysis
- **Auto Commit**: Results committed automatically
- **Pages Deploy**: Dashboard updates after each scan
- **Report Cleanup**: Old reports auto-deleted (90 days)

### Manual Trigger Options

1. Go to **Actions** → **FilterMapIR Daily Network Intelligence Scan**
2. Click **Run workflow**
3. Configure options:
   - 🔀 Enable Traceroute Analysis
   - 🔍 Deep Scan Mode
   - 🎯 Custom targets file

---

## 🌐 Setting Up GitHub Pages

1. Go to repository **Settings**
2. Navigate to **Pages** in sidebar
3. Under **Build and deployment**:
   - Source: **GitHub Actions**
4. After next workflow run, dashboard will be live at:
   ```
   https://YOUR-USERNAME.github.io/FilterMapIR/
   ```

---

## 📄 Output Formats

### JSON (summary.json)
Complete structured data with all test results and intelligence.

### CSV (summary.csv)
Spreadsheet-compatible export with key metrics.

### Markdown (summary.md)
Human-readable report with tables and status indicators.

---

## 🔒 Privacy & Security

| Aspect | Implementation |
|--------|----------------|
| **Scanner IP** | Never stored or displayed |
| **Location** | Only country and ISP shown |
| **Targets** | Only public services tested |
| **Credentials** | No secrets stored in repo |
| **Data** | All results publicly visible |

---

## 🤝 Contributing

Contributions welcome! Please:

1. Fork the repository
2. Create feature branch: `git checkout -b feature/amazing`
3. Commit changes: `git commit -m 'Add amazing feature'`
4. Push to branch: `git push origin feature/amazing`
5. Open a Pull Request

### Ideas for Contribution

- [ ] Add more target services
- [ ] Implement UDP testing
- [ ] Add email/webhook notifications
- [ ] Create API endpoint for results
- [ ] Add more visualization charts

---

## ⚠️ Disclaimer

This tool is provided for **educational and research purposes only**. 

- Only tests publicly accessible services
- Users must comply with applicable laws
- Maintainers are not responsible for misuse
- Not intended to circumvent any restrictions

---

## 📜 License

MIT License - see [LICENSE](LICENSE) file.

---

## 🙏 Acknowledgments

- [ip-api.com](https://ip-api.com/) - Geolocation data
- GitHub Actions - CI/CD infrastructure
- All contributors and testers

---

<div align="center">

**Made with ❤️ for network transparency**

[⬆ Back to Top](#filtermapir-️)

</div>
