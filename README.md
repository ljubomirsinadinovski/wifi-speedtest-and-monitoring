# Wi-Fi Monitor

A live, local dashboard for your Mac's network traffic. It shows how much data **each app** is
sending and receiving right now, your total Wi-Fi throughput, your Wi-Fi link quality, and runs a speed test.
You can record an app's traffic during a call and compare recordings side by side, for example a WhatsApp call against a Telegram call.

macOS only. There's nothing to install: it uses Python 3 and tools built into macOS.

## Features

- **Per-app traffic:** live download/upload rate, a 60-second sparkline and totals for every app.
  Click an app to see its 5-minute chart and the servers it's connected to.
- **All Wi-Fi traffic:** total throughput on the Wi-Fi interface, with a 5-minute chart.
- **Wi-Fi link:** signal, noise, signal-to-noise ratio, channel, band, standard and link rate.
- **Speed test:** download, upload, idle latency and responsiveness, using Apple's `networkQuality`.
- **Record & compare:** record one app's traffic during a call, then compare average and peak rates,
  total data used, and data per hour.
- Light and dark mode. Units switch between kbps/Mbps and KB/s/MB/s.

## Requirements

- macOS 12 (Monterey) or later
- Python 3.8+ (the one from Xcode Command Line Tools or Homebrew works)

## Usage

```bash
python3 wifimon.py
```

Or double-click `Start Wi-Fi Monitor.command` in Finder. The first time, macOS may block it:
right-click it, choose **Open**, then confirm.

The dashboard opens at http://127.0.0.1:8765. Press Ctrl+C, or close the Terminal window, to stop it.

| Option | Description |
|---|---|
| `--port 9000` | Use a different port (the next free port is tried automatically) |
| `--no-browser` | Don't open the browser on start |

### Comparing two apps

1. Start a call in the first app.
2. Under **Traffic by app**, click that app, enter a label (e.g. "WhatsApp video call") and press **Start recording**.
3. After a minute or two, press **Stop & save**.
4. Repeat with the other app. Both appear in the **Recordings** table.

For a fair comparison, use the same kind of call (voice or video) and similar lengths.

## How it works

`wifimon.py` is a single-file Python server (standard library only) that serves `index.html` and a small JSON API.

| Data | Source |
|---|---|
| Per-app / per-connection bytes | `nettop` (1-second deltas, localhost traffic excluded) |
| Wi-Fi interface totals | `netstat` |
| Wi-Fi link details | CoreWLAN via `ctypes`, which reads without triggering a Wi-Fi scan |
| Speed test | `networkQuality` |

## Privacy

Everything stays on your Mac. The server listens on `127.0.0.1` only. Recordings and speed test history
are saved next to the script, in `recordings.json` and `speedtests.json`. Both files are git-ignored.

## Notes

- With a VPN on, an app's traffic appears under the app, and again (encrypted) under the VPN's process.
- FaceTime calls run through a system service and appear as **FaceTime / Apple calls**.
  Safari traffic appears as **Safari / WebKit**.
- Background system services are hidden by default. Untick **Hide system services** to show them.
