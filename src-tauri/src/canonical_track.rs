// canonical_track.rs — Source-independent track identity layer
//
// Provides a CanonicalTrack type that represents the musical identity of a track
// independent of where it came from (local file, Beets, MTP device, scrobble).
// Matching is based on normalized metadata with optional MBID exact-match.

use log::info;
use rusqlite::{params, Connection, OpenFlags, OptionalExtension, Result};
use serde::{Deserialize, Serialize};
use tauri::Manager;
use uuid::Uuid;

use crate::metadata::Song;
use crate::mtp::MtpTrack;

// ─── Core types ───────────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct CanonicalTrack {
    pub id: String,
    pub mb_recording_id: Option<String>,
    pub artist: String,
    pub title: String,
    pub album: Option<String>,
    pub duration_secs: Option<f64>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct TrackSource {
    pub canonical_track_id: String,
    pub source_type: String,
    pub source_id: String,
    pub created_at: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct MatchResult {
    pub canonical_track: CanonicalTrack,
    pub confidence: f64,
    pub match_type: MatchType,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub enum MatchType {
    Mbid,
    Metadata,
    Created,
}

// ─── Normalization ────────────────────────────────────────────────────────────

/// Normalize a string for fuzzy comparison.
/// Lowercase, collapse whitespace, strip common suffixes, trim.
pub fn normalize(s: &str) -> String {
    let mut result = s.to_lowercase();

    // Strip common parenthetical suffixes
    for suffix in &[
        "(remastered)",
        "(remaster)",
        "(deluxe edition)",
        "(deluxe)",
        "(bonus track version)",
        "(bonus tracks)",
        "(expanded edition)",
        "(special edition)",
        "(anniversary edition)",
        "(original mix)",
        "(album version)",
        "(explicit)",
        "(clean)",
    ] {
        result = result.replace(suffix, "");
    }

    // Strip leading "the " from artist names
    if result.starts_with("the ") {
        result = result[4..].to_string();
    }

    // Collapse whitespace and trim
    result = result.split_whitespace().collect::<Vec<_>>().join(" ");
    result.trim().to_string()
}

// ─── Similarity scoring ──────────────────────────────────────────────────────

/// Compute similarity between two strings using a simple character-level
/// approach (Sørensen–Dice coefficient on bigrams).
fn string_similarity(a: &str, b: &str) -> f64 {
    if a == b {
        return 1.0;
    }
    if a.is_empty() || b.is_empty() {
        return 0.0;
    }
    if a.len() == 1 || b.len() == 1 {
        return if a == b { 1.0 } else { 0.0 };
    }

    let bigrams_a: Vec<(char, char)> = a.chars().zip(a.chars().skip(1)).collect();
    let bigrams_b: Vec<(char, char)> = b.chars().zip(b.chars().skip(1)).collect();

    let mut matches = 0;
    let mut used = vec![false; bigrams_b.len()];

    for ba in &bigrams_a {
        for (j, bb) in bigrams_b.iter().enumerate() {
            if !used[j] && ba == bb {
                matches += 1;
                used[j] = true;
                break;
            }
        }
    }

    (2.0 * matches as f64) / (bigrams_a.len() + bigrams_b.len()) as f64
}

/// Compute overall match confidence between two sets of track metadata.
/// Returns a score from 0.0 to 1.0.
///
/// Weights:
///   artist: 0.35
///   title:  0.40
///   album:  0.10
///   duration: 0.15
pub fn track_similarity(
    artist_a: &str,
    title_a: &str,
    album_a: Option<&str>,
    duration_a: Option<f64>,
    artist_b: &str,
    title_b: &str,
    album_b: Option<&str>,
    duration_b: Option<f64>,
) -> f64 {
    let na_artist = normalize(artist_a);
    let nb_artist = normalize(artist_b);
    let na_title = normalize(title_a);
    let nb_title = normalize(title_b);

    let artist_score = string_similarity(&na_artist, &nb_artist);
    let title_score = string_similarity(&na_title, &nb_title);

    let album_score = match (album_a, album_b) {
        (Some(a), Some(b)) => string_similarity(&normalize(a), &normalize(b)),
        _ => 0.5, // neutral when missing
    };

    let duration_score = match (duration_a, duration_b) {
        (Some(a), Some(b)) => {
            let diff = (a - b).abs();
            if diff < 1.0 {
                1.0
            } else if diff < 3.0 {
                0.8
            } else if diff < 5.0 {
                0.5
            } else if diff < 10.0 {
                0.2
            } else {
                0.0
            }
        }
        _ => 0.5, // neutral when missing
    };

    (artist_score * 0.35) + (title_score * 0.40) + (album_score * 0.10) + (duration_score * 0.15)
}

/// Minimum confidence to consider a match valid without user confirmation.
pub const MATCH_THRESHOLD: f64 = 0.75;

// ─── Conversion helpers ──────────────────────────────────────────────────────

/// Metadata extracted from any source for matching purposes.
pub struct TrackMetadata {
    pub artist: String,
    pub title: String,
    pub album: Option<String>,
    pub duration_secs: Option<f64>,
    pub mb_recording_id: Option<String>,
    pub source_type: String,
    pub source_id: String,
}

impl From<&Song> for TrackMetadata {
    fn from(song: &Song) -> Self {
        TrackMetadata {
            artist: song.artist.clone(),
            title: song.title.clone(),
            album: Some(song.album.clone()),
            duration_secs: song.file_info.duration,
            mb_recording_id: None, // musicat doesn't extract MBIDs yet
            source_type: if song.id.starts_with("beets-") {
                "beets".to_string()
            } else {
                "local".to_string()
            },
            source_id: song.id.clone(),
        }
    }
}

impl From<&MtpTrack> for TrackMetadata {
    fn from(track: &MtpTrack) -> Self {
        TrackMetadata {
            artist: track.artist.clone(),
            title: track.title.clone(),
            album: if track.album.is_empty() {
                None
            } else {
                Some(track.album.clone())
            },
            duration_secs: Some(track.duration_ms as f64 / 1000.0),
            mb_recording_id: None,
            source_type: "device:mtp".to_string(),
            source_id: track.item_id.to_string(),
        }
    }
}

// ─── SQLite database ─────────────────────────────────────────────────────────

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS canonical_tracks (
    id TEXT PRIMARY KEY,
    mb_recording_id TEXT,
    artist TEXT NOT NULL,
    title TEXT NOT NULL,
    album TEXT,
    duration_secs REAL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_ct_mbid ON canonical_tracks(mb_recording_id)
    WHERE mb_recording_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_ct_artist_title ON canonical_tracks(artist, title);

CREATE TABLE IF NOT EXISTS track_sources (
    canonical_track_id TEXT NOT NULL,
    source_type TEXT NOT NULL,
    source_id TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (source_type, source_id),
    FOREIGN KEY (canonical_track_id) REFERENCES canonical_tracks(id)
);

CREATE INDEX IF NOT EXISTS idx_ts_canonical ON track_sources(canonical_track_id);
";

/// Open (or create) the musicat canonical track database.
pub fn open_db(app_handle: &tauri::AppHandle) -> Result<Connection, String> {
    let config_dir = app_handle
        .path()
        .app_config_dir()
        .map_err(|e| format!("Failed to get config dir: {}", e))?;

    std::fs::create_dir_all(&config_dir)
        .map_err(|e| format!("Failed to create config dir: {}", e))?;

    let db_path = config_dir.join("musicat-tracks.db");

    let conn = Connection::open_with_flags(
        &db_path,
        OpenFlags::SQLITE_OPEN_READ_WRITE
            | OpenFlags::SQLITE_OPEN_CREATE
            | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .map_err(|e| format!("Failed to open tracks DB: {}", e))?;

    // Enable WAL mode for better concurrent read performance
    conn.execute_batch("PRAGMA journal_mode=WAL;")
        .map_err(|e| format!("Failed to set WAL mode: {}", e))?;

    conn.execute_batch(SCHEMA)
        .map_err(|e| format!("Failed to create schema: {}", e))?;

    Ok(conn)
}

// ─── Core operations ─────────────────────────────────────────────────────────

/// Find the best matching canonical track for the given metadata, or create one.
pub fn resolve(conn: &Connection, meta: &TrackMetadata) -> Result<MatchResult, String> {
    // 1. Check for existing source mapping (already resolved before)
    if let Some(ct) = find_by_source(conn, &meta.source_type, &meta.source_id)? {
        return Ok(MatchResult {
            canonical_track: ct,
            confidence: 1.0,
            match_type: MatchType::Metadata, // previously resolved
        });
    }

    // 2. Try MBID exact match
    if let Some(ref mbid) = meta.mb_recording_id {
        if let Some(ct) = find_by_mbid(conn, mbid)? {
            // Record the source mapping
            insert_source(conn, &ct.id, &meta.source_type, &meta.source_id)?;
            return Ok(MatchResult {
                canonical_track: ct,
                confidence: 1.0,
                match_type: MatchType::Mbid,
            });
        }
    }

    // 3. Fuzzy metadata match against existing canonical tracks
    let candidates = find_candidates(conn, &meta.artist, &meta.title)?;
    let mut best_match: Option<(CanonicalTrack, f64)> = None;

    for candidate in candidates {
        let score = track_similarity(
            &meta.artist,
            &meta.title,
            meta.album.as_deref(),
            meta.duration_secs,
            &candidate.artist,
            &candidate.title,
            candidate.album.as_deref(),
            candidate.duration_secs,
        );

        if score >= MATCH_THRESHOLD {
            match &best_match {
                Some((_, best_score)) if score <= *best_score => {}
                _ => best_match = Some((candidate, score)),
            }
        }
    }

    if let Some((ct, score)) = best_match {
        // Record the source mapping
        insert_source(conn, &ct.id, &meta.source_type, &meta.source_id)?;
        return Ok(MatchResult {
            canonical_track: ct,
            confidence: score,
            match_type: MatchType::Metadata,
        });
    }

    // 4. No match — create a new canonical track (phantom if no library link)
    let ct = create_canonical_track(conn, meta)?;
    insert_source(conn, &ct.id, &meta.source_type, &meta.source_id)?;

    Ok(MatchResult {
        canonical_track: ct,
        confidence: 1.0,
        match_type: MatchType::Created,
    })
}

fn find_by_source(
    conn: &Connection,
    source_type: &str,
    source_id: &str,
) -> Result<Option<CanonicalTrack>, String> {
    let mut stmt = conn
        .prepare(
            "SELECT ct.id, ct.mb_recording_id, ct.artist, ct.title, ct.album,
                    ct.duration_secs, ct.created_at, ct.updated_at
             FROM canonical_tracks ct
             JOIN track_sources ts ON ct.id = ts.canonical_track_id
             WHERE ts.source_type = ?1 AND ts.source_id = ?2",
        )
        .map_err(|e| e.to_string())?;

    let result = stmt
        .query_row(params![source_type, source_id], row_to_canonical_track)
        .optional()
        .map_err(|e| e.to_string())?;

    Ok(result)
}

fn find_by_mbid(conn: &Connection, mbid: &str) -> Result<Option<CanonicalTrack>, String> {
    let mut stmt = conn
        .prepare(
            "SELECT id, mb_recording_id, artist, title, album, duration_secs,
                    created_at, updated_at
             FROM canonical_tracks
             WHERE mb_recording_id = ?1",
        )
        .map_err(|e| e.to_string())?;

    let result = stmt
        .query_row(params![mbid], row_to_canonical_track)
        .optional()
        .map_err(|e| e.to_string())?;

    Ok(result)
}

/// Find candidate canonical tracks that could match the given artist/title.
/// Uses normalized prefix matching to narrow candidates before scoring.
fn find_candidates(
    conn: &Connection,
    artist: &str,
    title: &str,
) -> Result<Vec<CanonicalTrack>, String> {
    // Use the first few characters of normalized artist and title for a rough filter.
    // This avoids scanning the entire table while still catching variations.
    let norm_artist = normalize(artist);
    let norm_title = normalize(title);
    let artist_prefix = if norm_artist.len() >= 3 {
        &norm_artist[..3]
    } else {
        &norm_artist
    };
    let title_prefix = if norm_title.len() >= 3 {
        &norm_title[..3]
    } else {
        &norm_title
    };

    let mut stmt = conn
        .prepare(
            "SELECT id, mb_recording_id, artist, title, album, duration_secs,
                    created_at, updated_at
             FROM canonical_tracks
             WHERE LOWER(artist) LIKE ?1 AND LOWER(title) LIKE ?2
             LIMIT 100",
        )
        .map_err(|e| e.to_string())?;

    let pattern = format!("{}%", artist_prefix);
    let title_pattern = format!("{}%", title_prefix);
    let rows = stmt
        .query_map(params![pattern, title_pattern], row_to_canonical_track)
        .map_err(|e| e.to_string())?;

    let mut results = Vec::new();
    for row in rows {
        results.push(row.map_err(|e| e.to_string())?);
    }
    Ok(results)
}

fn create_canonical_track(
    conn: &Connection,
    meta: &TrackMetadata,
) -> Result<CanonicalTrack, String> {
    let id = Uuid::new_v4().to_string();
    let now = chrono::Utc::now().to_rfc3339();

    conn.execute(
        "INSERT INTO canonical_tracks (id, mb_recording_id, artist, title, album, duration_secs, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            id,
            meta.mb_recording_id,
            meta.artist,
            meta.title,
            meta.album,
            meta.duration_secs,
            now,
            now,
        ],
    )
    .map_err(|e| e.to_string())?;

    Ok(CanonicalTrack {
        id,
        mb_recording_id: meta.mb_recording_id.clone(),
        artist: meta.artist.clone(),
        title: meta.title.clone(),
        album: meta.album.clone(),
        duration_secs: meta.duration_secs,
        created_at: now.clone(),
        updated_at: now,
    })
}

fn insert_source(
    conn: &Connection,
    canonical_track_id: &str,
    source_type: &str,
    source_id: &str,
) -> Result<(), String> {
    conn.execute(
        "INSERT OR IGNORE INTO track_sources (canonical_track_id, source_type, source_id)
         VALUES (?1, ?2, ?3)",
        params![canonical_track_id, source_type, source_id],
    )
    .map_err(|e| e.to_string())?;
    Ok(())
}

fn row_to_canonical_track(row: &rusqlite::Row) -> rusqlite::Result<CanonicalTrack> {
    Ok(CanonicalTrack {
        id: row.get(0)?,
        mb_recording_id: row.get(1)?,
        artist: row.get(2)?,
        title: row.get(3)?,
        album: row.get(4)?,
        duration_secs: row.get(5)?,
        created_at: row.get(6)?,
        updated_at: row.get(7)?,
    })
}

// ─── Tauri commands ──────────────────────────────────────────────────────────

/// Resolve a track to its canonical identity. Creates one if no match is found.
#[tauri::command]
pub async fn resolve_canonical_track(
    artist: String,
    title: String,
    album: Option<String>,
    duration_secs: Option<f64>,
    source_type: String,
    source_id: String,
    mb_recording_id: Option<String>,
    app_handle: tauri::AppHandle,
) -> Result<MatchResult, String> {
    let meta = TrackMetadata {
        artist,
        title,
        album,
        duration_secs,
        mb_recording_id,
        source_type,
        source_id,
    };

    let conn = open_db(&app_handle)?;
    resolve(&conn, &meta)
}

/// Get a canonical track by ID.
#[tauri::command]
pub async fn get_canonical_track(
    id: String,
    app_handle: tauri::AppHandle,
) -> Result<Option<CanonicalTrack>, String> {
    let conn = open_db(&app_handle)?;
    let mut stmt = conn
        .prepare(
            "SELECT id, mb_recording_id, artist, title, album, duration_secs,
                    created_at, updated_at
             FROM canonical_tracks WHERE id = ?1",
        )
        .map_err(|e| e.to_string())?;

    let result = stmt
        .query_row(params![id], row_to_canonical_track)
        .optional()
        .map_err(|e| e.to_string())?;

    Ok(result)
}

/// Get all sources for a canonical track.
#[tauri::command]
pub async fn get_track_sources(
    canonical_track_id: String,
    app_handle: tauri::AppHandle,
) -> Result<Vec<TrackSource>, String> {
    let conn = open_db(&app_handle)?;
    let mut stmt = conn
        .prepare(
            "SELECT canonical_track_id, source_type, source_id, created_at
             FROM track_sources WHERE canonical_track_id = ?1",
        )
        .map_err(|e| e.to_string())?;

    let rows = stmt
        .query_map(params![canonical_track_id], |row| {
            Ok(TrackSource {
                canonical_track_id: row.get(0)?,
                source_type: row.get(1)?,
                source_id: row.get(2)?,
                created_at: row.get(3)?,
            })
        })
        .map_err(|e| e.to_string())?;

    let mut results = Vec::new();
    for row in rows {
        results.push(row.map_err(|e| e.to_string())?);
    }
    Ok(results)
}

/// Find a canonical track by source type and source ID.
#[tauri::command]
pub async fn find_canonical_by_source(
    source_type: String,
    source_id: String,
    app_handle: tauri::AppHandle,
) -> Result<Option<CanonicalTrack>, String> {
    let conn = open_db(&app_handle)?;
    find_by_source(&conn, &source_type, &source_id)
}

/// Batch-resolve multiple songs to canonical tracks.
/// Useful for resolving an entire library or album at once.
#[tauri::command]
pub async fn batch_resolve_songs(
    songs: Vec<Song>,
    app_handle: tauri::AppHandle,
) -> Result<Vec<MatchResult>, String> {
    let conn = open_db(&app_handle)?;
    let mut results = Vec::with_capacity(songs.len());

    // Use a transaction for performance
    let tx = conn.unchecked_transaction().map_err(|e| e.to_string())?;

    for song in &songs {
        let meta = TrackMetadata::from(song);
        let result = resolve(&tx, &meta)?;
        results.push(result);
    }

    tx.commit().map_err(|e| e.to_string())?;

    info!(
        "[CanonicalTrack] Batch resolved {} songs",
        results.len()
    );
    Ok(results)
}
