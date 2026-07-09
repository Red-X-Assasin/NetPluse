# NetPulse

NetPulse is a local packet-sniffing prototype for monitoring traffic on your own machine or a local network. It provides a simple web UI, live capture controls, filtering, a packet feed, detail inspection, and export options.

## Requirements

- Python 3.10+
- Administrator/root privileges are often required for raw packet capture.
- The app only inspects traffic on interfaces you choose and should be used only on networks you are authorized to monitor.

## Setup

1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
2. Start the server:
   ```bash
   python -m uvicorn app.main:app --reload
   ```
3. Open http://127.0.0.1:8000/

## Notes

- The app is intentionally simple and safe: it does not execute payload content, it only displays it.
- Packet capture may fail on systems without permissions or with missing interfaces.
