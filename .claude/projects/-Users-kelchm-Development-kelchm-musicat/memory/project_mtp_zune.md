---
name: MTP/Zune sync implementation status
description: Current state of the MTP sync feature including Zune MTPZ handshake — what works, key architecture decisions, and known quirks
type: project
---

MTP device sync feature on branch `feat/mtp-sync`. Uses `mtp-rs` (pure Rust, path dep at `../../mtp-rs`) instead of libmtp C bindings.

**What works (2026-04-04):**
- Generic MTP: device detection, track listing with metadata, file upload (tested on Pixel 6a)
- Zune MTPZ handshake: full 4-phase crypto auth (RSA-1024 + AES-128-CBC + SHA-1 + CMAC)
- Zune track listing: 548 tracks with artist, album, play counts all populated
- Frontend: ZuneSyncView.svelte in sidebar

**Key mtp-rs modifications (local checkout at ../../mtp-rs):**
- `session()` public accessor on MtpDevice for low-level PTP property queries
- `execute`, `execute_with_send`, `execute_with_receive` made public on PtpSession
- Split header/data mode: Zune requires PTP data container header and payload sent as separate USB bulk transfers. Auto-detected via `is_known_mtp_device()` VID/PID table
- `set_configuration(1)` fallback for unconfigured USB devices
- Accept class=0 interfaces with MTP endpoint layout (Zune doesn't use standard MTP class codes)
- `needs_manual_traversal()` for Microsoft devices (native recursive listing doesn't work)
- Zune VID/PID table: (0x045E, 0x0710/0711/0712/063E/0714)

**Key musicat decisions:**
- Device identification via serial number (string) not location_id (u64 precision loss through JSON)
- MTPZ credentials loaded from ~/.mtpz-data (5 hex lines, sourced from libmtp-zune repo)
- Track listing does manual folder walk with error-skip (Zune has abstract objects that fail GetObjectInfo)
- SetObjectPropValue gated on `supports_rename()` (Android doesn't support it; reads ID3 tags instead)

**Why:** Zune support on macOS without needing Windows/libmtp-zune C dependency chain.

**How to apply:** When working on MTP features, be aware of Zune-specific quirks above. The mtp-rs changes should be upstreamed.
