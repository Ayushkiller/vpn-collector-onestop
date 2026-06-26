# VPN-Detect Collector (one app)

A research data-collection app for a Delhi Technological University study on VPN/tunnel
detection. It captures **header-only** network metadata (packet sizes, timing, ports —
**never message content or payload**) and streams it to a research collector, so we can
study which kinds of VPN traffic a privacy-respecting detector can and cannot identify.

This is a **single app** — the capture engine is built in (forked from
[PCAPdroid](https://github.com/emanuele-f/PCAPdroid), GPLv3). No companion app required.

> **Privacy in one line:** it records the *size and timing* of packets, like noting "a
> 1200-byte packet left at 14:03" — it never opens the packet, never reads your messages,
> browsing, or any app content.

## Install (volunteers)

1. **Download the APK:** http://4.247.129.247:8080/app
   (before installing, enable "Install unknown apps" for your browser.)
2. Open the app, tap **Start**, and grant the one-time VPN permission it requests
   (this is how Android lets it capture — it is **not** a real VPN and uses no remote server).
3. Use your phone normally. That's it — it streams header-only metadata to the collector.

- **Header-only by default** (payload capture is hard-disabled in this fork).
- **Your own VPN is untouched.** If you turn on WireGuard/Nord/any VPN, this app stops
  automatically (Android allows only one VPN at a time) and resumes when it's off.
- **Stop anytime** from the app's stop button or the notification.

## What changed from PCAPdroid

This fork adds a small `HttpDumper` that streams the live header-only PCAP to the campaign
collector over one chunked HTTP POST (on a protected socket, so the upload itself is never
captured), and preconfigures the app for one-tap collection (collector address, header-only
payload mode, exporter dump mode). See `app/src/main/java/com/emanuelef/remote_capture/pcap_dump/HttpDumper.java`.

The collector endpoint is token-protected and size-capped and stores only header-only
`.pcap` files. No payload is ever transmitted.

## License & credit

PCAPdroid is © Emanuele Faranda, licensed **GPLv3** (see `COPYING`). This research fork
keeps the same license. All original PCAPdroid functionality and credit remain with the
upstream project: https://github.com/emanuele-f/PCAPdroid

---

*Department of Computer Science and Engineering, Delhi Technological University.
Header-only, consent-based, opt-out anytime.*
