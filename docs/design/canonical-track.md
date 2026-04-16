# CanonicalTrack: Source-Independent Track Identity

## Status: RFC / Prototype

## Problem

Musicat currently has no stable, source-independent track identity. Every source
produces its own ID:

| Source | ID format | Example |
|--------|-----------|---------|
| Local library (Dexie) | `MD5(filepath)` | `"a3f8c9..."` |
| Beets integration | `"beets-{db_id}"` | `"beets-4217"` |
| MTP device (Zune) | MTP object handle | `0x003F` |
| Rockbox `.scrobbler.log` | none — just metadata | artist/title/duration |
| Last.fm scrobble | none — just metadata | artist/title/timestamp |

The same song from two different sources has no shared identity. This creates
several concrete problems:

1. **Beets must be a hard switch.** The Beets integration replaces Dexie as the
   library source — it can't coexist because there's no way to deduplicate
   tracks across the two. (`CanvasLibraryView.svelte:47`, `AlbumsView.svelte:73`)

2. **Play counts silently break in Beets mode.** `incrementPlayCounter` in
   `AudioPlayer.ts:604` calls `db.songs.update()` on Dexie, but in Beets mode
   the Song came from `invoke("search_beets")` — the Dexie row doesn't exist,
   so the update is a no-op.

3. **Device sync can't correlate tracks.** When syncing to/from a Zune or
   Rockbox device, we need to answer "which library track does this device track
   correspond to?" The device doesn't share file paths or database IDs.

4. **Play history from external sources can't be attributed.** A Last.fm
   scrobble or a Rockbox `.scrobbler.log` entry has artist/title/duration but no
   musicat-native ID. Without a matching layer, this data has nowhere to land.

## Proposal: CanonicalTrack

A `CanonicalTrack` represents the musical identity of a track, independent of
where it came from. It's the layer that says "these three references — a local
file, a Beets entry, and a Zune track — are all the same piece of music."

### Core struct

```rust
struct CanonicalTrack {
    id: String,                     // UUID
    mb_recording_id: Option<String>, // MusicBrainz recording ID (authoritative when present)
    artist: String,                 // normalized for matching
    title: String,                  // normalized for matching
    album: Option<String>,          // normalized for matching
    duration_secs: Option<f64>,     // matching confidence signal
    created_at: String,             // ISO 8601
    updated_at: String,             // ISO 8601
}
```

### Source mappings

Each source that references a canonical track gets a `TrackSource` entry:

```rust
struct TrackSource {
    canonical_track_id: String,
    source_type: String,   // "local", "beets", "device:zune:SERIAL", etc.
    source_id: String,     // source-specific ID (MD5 hash, beets-id, MTP handle)
    created_at: String,
}
```

This is how one canonical track can be "the same song" across multiple places.

### Matching / resolution

Given an external track reference (device track, scrobble, Beets entry), resolve
it to a CanonicalTrack:

1. **MBID match** — if both sides have a MusicBrainz recording ID, exact match.
2. **Fuzzy metadata match** — normalize artist + title, compare with similarity
   scoring. Duration acts as a confidence signal (~3s tolerance = strong match,
   outside = suspicious). Album as optional tiebreaker.
3. **No match → phantom track** — create a new CanonicalTrack with no library
   link. Play history can still attach to it. If the track later appears in the
   library, it resolves via background re-matching.

Normalization:
- Lowercase
- Strip leading "The " from artist
- Collapse whitespace
- Strip common suffixes: "(Remastered)", "(Deluxe Edition)", etc.
- Unicode normalization (NFC)

### Where user data lives

Play events, favorites, tags, and other user data attach to `CanonicalTrack`,
not to source-specific instances. This means:

- Play counts survive file renames (new local ID, same canonical track)
- Plays from devices attribute to the right canonical track
- Beets and local library tracks share a single play history
- Future: Last.fm scrobble imports land on canonical tracks

### Relationship to existing types

```
┌─────────────┐     ┌────────────────┐     ┌──────────────┐
│ Song (Dexie) │────▶│ CanonicalTrack │◀────│ MtpTrack     │
│ id: MD5(path)│     │ id: UUID       │     │ item_id: u32 │
└─────────────┘     └────────────────┘     └──────────────┘
                           ▲
                    ┌──────┘
                    │
              ┌─────────────┐
              │ Beets row   │
              │ id: beets-N │
              └─────────────┘
```

## Storage

CanonicalTrack and TrackSource live in a Rust-owned SQLite database, separate
from the Dexie library store and the read-only Beets database.

Rationale:
- Rust already has `rusqlite` (used for Beets integration)
- Play history queries need aggregates, joins, and FTS — capabilities IndexedDB
  lacks
- This is musicat's own persistent state, not an external integration
- Long-term, the library itself may migrate from Dexie to this SQLite store,
  consolidating to a single owned database

The Beets database remains a read-only external integration — it's not "our"
database, same category as a Subsonic server or Last.fm API.

## Integration plan

### Phase 1: Foundation (this PR)
- `CanonicalTrack` struct and SQLite schema
- Normalization and similarity scoring
- `From<&Song>` and `From<&MtpTrack>` conversions
- Tauri commands: resolve, search, get by ID
- Basic matching: find-or-create canonical track for a given Song/MtpTrack

### Phase 2: Device sync integration
- When syncing tracks to a device, store `TrackSource` mapping (canonical_id →
  MTP object handle)
- On subsequent syncs, use stored mappings instead of re-matching
- Pull play counts from device, attribute to canonical track

### Phase 3: Play history
- `PlayRecord` table: per-play events with timestamps and source attribution
- `BaselinePlayCount` table: for count-only sources (Zune, legacy musicat)
- Migrate existing `Song.playCount` to baseline counts
- Scrobbler integration: emit PlayRecords from playback events

### Phase 4: Beets coexistence
- Extract MBIDs from Beets (`mb_trackid` is available but not currently queried)
- Resolve Beets tracks to canonical tracks on import/sync
- Allow Beets and local library to coexist rather than being mutually exclusive

### Phase 5: Library consolidation (future)
- Evaluate migrating Dexie library data to SQLite
- Requires solving the `liveQuery` reactivity replacement
- End state: one SQLite database for all musicat-owned state

## Open questions

1. **Normalization depth.** How aggressive should string normalization be? Too
   aggressive and we false-positive on different tracks; too conservative and we
   miss obvious matches. Need to tune with real data.

2. **Similarity threshold.** What score constitutes a "confident match" vs.
   "needs user confirmation"? Multi-scrobbler uses a weighted scoring model
   (0.3/0.4/0.5 with 1.0 threshold) worth studying.

3. **MBID sourcing.** Beets has MBIDs but musicat doesn't currently extract
   them. Local files may have them in ID3 tags. Should we read them during scan?

4. **Reactivity.** How does the TS side know when canonical tracks change?
   Options: Tauri event bus notifications, polling, or a thin reactive layer
   over invoke calls.

## References

- GitHub discussion: basharovV/musicat#182 (Extension Points)
- Multi-scrobbler dedup model: weighted scoring + temporal accuracy tiers
- MusicBrainz recording ID as canonical identity
