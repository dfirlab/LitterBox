# LitterBox Deployment Guide (ADSIM-AI Fork)

## Overview

This is the ADSIM-AI fork of [BlackSnufkin/LitterBox](https://github.com/BlackSnufkin/LitterBox).

**Key change**: Upload file storage uses SHA256-prefixed filenames (was MD5) for compatibility with the ADSIM-AI integration which passes SHA256 hashes for analysis requests.

## Prerequisites

- Windows 10/11 or Windows Server 2019+
- Python 3.11+
- Administrator privileges (required for dynamic analysis tools)
- [NSSM](https://nssm.cc/) (Non-Sucking Service Manager) for Windows service

## Installation

```powershell
# Clone the forked repo
git clone https://github.com/dfirlab/LitterBox.git C:\LitterBox
cd C:\LitterBox

# Install Python dependencies
pip install -r requirements.txt

# Verify it starts
python litterbox.py --ip 0.0.0.0
# Should show: "Running on http://0.0.0.0:1337"
# Ctrl+C to stop
```

## Windows Service Setup (NSSM)

```powershell
# Download NSSM from https://nssm.cc/download
# Extract to C:\nssm\

# Install the service
C:\nssm\nssm.exe install LitterBox "C:\Python311\python.exe" "C:\LitterBox\litterbox.py --ip 0.0.0.0"
C:\nssm\nssm.exe set LitterBox AppDirectory "C:\LitterBox"
C:\nssm\nssm.exe set LitterBox Start SERVICE_AUTO_START
C:\nssm\nssm.exe set LitterBox AppRestartDelay 5000
C:\nssm\nssm.exe set LitterBox Description "LitterBox Malware Analysis Sandbox"

# Start the service
C:\nssm\nssm.exe start LitterBox

# Verify
curl http://localhost:1337/health
```

## Service Management

```powershell
# Status
C:\nssm\nssm.exe status LitterBox

# Stop
C:\nssm\nssm.exe stop LitterBox

# Restart
C:\nssm\nssm.exe restart LitterBox

# Remove service
C:\nssm\nssm.exe remove LitterBox confirm
```

## Firewall

```powershell
# Allow inbound TCP 1337 from RTAA network
netsh advfirewall firewall add rule name="LitterBox" dir=in action=allow protocol=TCP localport=1337
```

## ADSIM-AI Integration

In the RTAA `.env` file:
```
LITTERBOX_URL=http://172.13.1.197:1337
```

## Migration from MD5-prefixed Storage

If you have existing uploads with MD5-prefixed filenames:

```powershell
cd C:\LitterBox
python scripts\migrate_hashes.py --dry-run   # Preview
python scripts\migrate_hashes.py              # Execute
```

## SHA256 Fix Details

**What changed**: `app/utils.py` line 790 — filename construction uses SHA256 instead of MD5:
```python
# Before: filename = f"{md5_hash}_{original_filename}"
# After:  filename = f"{sha256_hash}_{original_filename}"
```

This ensures that when ADSIM-AI calls `/analyze/static/{sha256}`, the `find_file_by_hash()` prefix match finds the file. MD5 hash is still computed and stored in `file_info.json` — no data is lost.

## Troubleshooting

| Issue | Fix |
|-------|-----|
| Service won't start | Check Python path in NSSM: `nssm.exe edit LitterBox` |
| 404 on analyze after upload | Verify file in `Uploads/` has SHA256 prefix (64 chars) |
| Dynamic analysis fails | Ensure running as Administrator / Local System |
| Connection refused | Check firewall rule + service status |
| Old uploads not found | Run `scripts/migrate_hashes.py` |

## Logs

NSSM captures stdout/stderr. Configure log files:
```powershell
C:\nssm\nssm.exe set LitterBox AppStdout C:\LitterBox\logs\stdout.log
C:\nssm\nssm.exe set LitterBox AppStderr C:\LitterBox\logs\stderr.log
mkdir C:\LitterBox\logs
C:\nssm\nssm.exe restart LitterBox
```
