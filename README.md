# Network Diagnosis Tool

A Windows desktop application for packet capture analysis and network troubleshooting.

Features:
- Import PCAP files for offline visual analysis
- Capture live network traffic on supported Windows NICs
- Detect common problems such as packet loss, retransmission, DNS failures, handshake errors, and broadcast storms
- Display expert recommendations and root-cause hints
- Export a human-readable diagnosis report
- Build as a Windows EXE with PyInstaller

## Project structure

- `main.py` - application entry point
- `network_tool/capture.py` - packet capture and parsing helpers
- `network_tool/diagnostics.py` - issue detection and recommendations
- `network_tool/gui.py` - Tkinter-based desktop UI
- `build_exe.py` - PyInstaller build automation
- `installer/network_diagnosis_tool.iss` - Inno Setup installer template
