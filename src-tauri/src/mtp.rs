// mtp.rs — MTP device sync via mtp-rs (pure Rust, no libmtp/FFI)
//
// Provides device detection, track metadata (including play counts),
// and file transfer for any MTP device. Uses standard MTP object
// property codes — not Zune-specific.

use bytes::Bytes;
use futures_util::stream;
use log::info;
use mtp_rs::mtp::{MtpDevice, MtpDeviceInfo, NewObjectInfo};
use mtp_rs::ptp::{
    pack_string, unpack_string, unpack_u16, unpack_u32, ObjectFormatCode, ObjectHandle,
    ObjectPropertyCode,
};
use mtp_rs::Progress;
use serde::{Deserialize, Serialize};
use std::ops::ControlFlow;
use std::path::Path;
use std::sync::Arc;
use tauri::Emitter;
use tokio::sync::Mutex;

use crate::mtpz;

// ─── Zune device identification ─────────────────────────────────────────
// Microsoft Zune VID/PIDs — these devices use non-standard USB descriptors
// (so they need to be passed to `list_devices_with_known`) and require
// split header/data mode on the data phase of `execute_with_send`.

const ZUNE_DEVICES: &[(u16, u16)] = &[
    (0x045E, 0x0710), // Zune
    (0x045E, 0x0711), // Zune
    (0x045E, 0x0712), // Zune
    (0x045E, 0x063E), // Zune HD
    (0x045E, 0x0714), // Zune (alt)
];

fn is_zune(vendor_id: u16, product_id: u16) -> bool {
    ZUNE_DEVICES
        .iter()
        .any(|&(v, p)| v == vendor_id && p == product_id)
}

// ─── Standard MTP object property codes for music metadata ────────────────
// See MTP spec §5.3.12 — these work on any compliant MTP device.

/// Artist name (string)
const OPC_ARTIST: ObjectPropertyCode = ObjectPropertyCode::Unknown(0xDC46);
/// Album name (string) — only readable on track objects; for writes it must
/// be set on the abstract AbstractAudioAlbum object instead.
const OPC_ALBUM_NAME: ObjectPropertyCode = ObjectPropertyCode::Unknown(0xDC9A);
/// Track title / display name
const OPC_NAME: ObjectPropertyCode = ObjectPropertyCode::Name;
/// Genre (string)
const OPC_GENRE: ObjectPropertyCode = ObjectPropertyCode::Unknown(0xDC8C);
/// Track number (u16)
const OPC_TRACK: ObjectPropertyCode = ObjectPropertyCode::Unknown(0xDC8B);
/// Duration in milliseconds (u32)
const OPC_DURATION: ObjectPropertyCode = ObjectPropertyCode::Unknown(0xDC89);
/// Use count / play count (u32)
const OPC_USE_COUNT: ObjectPropertyCode = ObjectPropertyCode::Unknown(0xDC91);
/// ArtistId — links a track or album object to an Artist object (uint32 handle)
const OPC_ARTIST_ID: ObjectPropertyCode = ObjectPropertyCode::Unknown(0xDAB9);
/// RepresentativeSampleData — raw image bytes for album art (byte array)
const OPC_REP_SAMPLE_DATA: ObjectPropertyCode = ObjectPropertyCode::Unknown(0xDC86);
/// RepresentativeSampleFormat — image format code (u16, 0x3801 = JPEG)
const OPC_REP_SAMPLE_FORMAT: ObjectPropertyCode = ObjectPropertyCode::Unknown(0xDC81);

/// Object format for an Artist metadata object (Zune extension).
const OFC_ARTIST: u16 = 0xB218;
/// Object format for an AbstractAudioAlbum object (standard MTP).
const OFC_ABSTRACT_AUDIO_ALBUM: u16 = 0xBA03;

// ─── Data types for Tauri serialization ───────────────────────────────────

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct MtpDeviceDesc {
    pub vendor_id: u16,
    pub product_id: u16,
    pub manufacturer: String,
    pub product: String,
    pub serial_number: String,
}

impl From<&MtpDeviceInfo> for MtpDeviceDesc {
    fn from(d: &MtpDeviceInfo) -> Self {
        Self {
            vendor_id: d.vendor_id,
            product_id: d.product_id,
            manufacturer: d.manufacturer.clone().unwrap_or_default(),
            product: d.product.clone().unwrap_or_default(),
            serial_number: d.serial_number.clone().unwrap_or_default(),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct MtpTrack {
    pub handle: u32,
    pub title: String,
    pub artist: String,
    pub album: String,
    pub genre: String,
    pub track_number: u16,
    pub duration_ms: u32,
    pub play_count: u32,
    pub filename: String,
    pub filesize: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct SendTrackRequest {
    pub file_path: String,
    pub title: String,
    pub artist: String,
    pub album: String,
    pub genre: String,
    pub track_number: u16,
    pub duration_ms: u32,
    pub serial_number: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct SendTrackProgress {
    pub bytes_sent: u64,
    pub bytes_total: u64,
    pub percent: f64,
    pub file_path: String,
}

// ─── Shared device connection ─────────────────────────────────────────────

/// Per-album state we maintain across uploads in the same session.
#[derive(Default, Clone)]
struct AlbumGroup {
    artist_handle: ObjectHandle,
    album_handle: ObjectHandle,
    track_handles: Vec<ObjectHandle>,
}

/// Holds an open MTP device connection so we don't re-open for every command.
struct DeviceConnection {
    device: MtpDevice,
    serial: String,
    vendor_id: u16,
    product_id: u16,
    /// Map of artist name → artist object handle (created on demand)
    artist_handles: std::collections::HashMap<String, ObjectHandle>,
    /// Map of "artist|||album" → AlbumGroup (created on demand)
    album_groups: std::collections::HashMap<String, AlbumGroup>,
}

// We use a simple mutex-guarded Option for connection caching.
static DEVICE: std::sync::OnceLock<Arc<Mutex<Option<DeviceConnection>>>> = std::sync::OnceLock::new();

fn device_holder() -> &'static Arc<Mutex<Option<DeviceConnection>>> {
    DEVICE.get_or_init(|| Arc::new(Mutex::new(None)))
}

/// Get or open a device connection by serial number. Returns the open
/// device along with its USB vid/pid so callers can dispatch device-specific
/// behavior (e.g., Zune-only upload paths).
async fn get_device(serial: &str) -> Result<(MtpDevice, u16, u16), String> {
    let holder = device_holder();
    let mut guard = holder.lock().await;

    // Reuse existing connection if same device
    if let Some(conn) = guard.as_ref() {
        if conn.serial == serial {
            return Ok((conn.device.clone(), conn.vendor_id, conn.product_id));
        }
    }

    // Look up vid/pid via mtp-rs discovery (using the same known-devices list
    // we pass to the open call) so we can dispatch device-specific behavior
    // after open. mtp-rs handles enumeration, the macOS configuration quirk,
    // and the permissive interface scan internally.
    let (vid, pid) = MtpDevice::list_devices_with_known(ZUNE_DEVICES)
        .map_err(|e| format!("Failed to enumerate MTP devices: {}", e))?
        .into_iter()
        .find(|d| d.serial_number.as_deref() == Some(serial))
        .map(|d| (d.vendor_id, d.product_id))
        .ok_or_else(|| format!("No MTP device with serial {}", serial))?;

    let device = MtpDevice::builder()
        .known_devices(ZUNE_DEVICES)
        .open_by_serial(serial)
        .await
        .map_err(|e| {
            if e.is_exclusive_access() {
                "Another application has exclusive access to this device. \
                 Close other apps that might be using it (e.g. Image Capture, \
                 Android File Transfer) and try again."
                    .to_string()
            } else {
                format!("Failed to open MTP session: {}", e)
            }
        })?;

    // Apply Zune quirk: data container header and payload must be sent as
    // separate USB bulk transfers in execute_with_send.
    if is_zune(vid, pid) {
        device.session().set_split_header_data(true);
    }

    info!(
        "Opened MTP device: {} {}",
        device.device_info().manufacturer,
        device.device_info().model
    );

    // Perform MTPZ handshake if the device requires it (e.g., Zune)
    if mtpz::device_needs_mtpz(&device) {
        info!("Device requires MTPZ authentication");
        mtpz::perform_handshake(&device).await?;
    }

    *guard = Some(DeviceConnection {
        device: device.clone(),
        serial: serial.to_string(),
        vendor_id: vid,
        product_id: pid,
        artist_handles: std::collections::HashMap::new(),
        album_groups: std::collections::HashMap::new(),
    });

    Ok((device, vid, pid))
}

// ─── Property reading helpers ─────────────────────────────────────────────

/// Read a string property from an object, returning empty string on failure.
async fn read_string_prop(
    device: &MtpDevice,
    handle: ObjectHandle,
    prop: ObjectPropertyCode,
) -> String {
    match device.session().get_object_prop_value(handle, prop).await {
        Ok(bytes) if !bytes.is_empty() => {
            unpack_string(&bytes).map(|(s, _)| s).unwrap_or_default()
        }
        _ => String::new(),
    }
}

/// Read a u32 property from an object, returning 0 on failure.
async fn read_u32_prop(
    device: &MtpDevice,
    handle: ObjectHandle,
    prop: ObjectPropertyCode,
) -> u32 {
    match device.session().get_object_prop_value(handle, prop).await {
        Ok(bytes) if bytes.len() >= 4 => unpack_u32(&bytes).unwrap_or(0),
        _ => 0,
    }
}

/// Read a u16 property from an object, returning 0 on failure.
async fn read_u16_prop(
    device: &MtpDevice,
    handle: ObjectHandle,
    prop: ObjectPropertyCode,
) -> u16 {
    match device.session().get_object_prop_value(handle, prop).await {
        Ok(bytes) if bytes.len() >= 2 => unpack_u16(&bytes).unwrap_or(0),
        _ => 0,
    }
}

/// Check if an object format is an audio type we care about.
fn is_audio_format(format: ObjectFormatCode) -> bool {
    format.is_audio()
}

// ─── Tauri commands ───────────────────────────────────────────────────────

#[tauri::command]
pub async fn mtp_detect_devices() -> Result<Vec<MtpDeviceDesc>, String> {
    tokio::task::spawn_blocking(|| {
        MtpDevice::list_devices_with_known(ZUNE_DEVICES)
            .map(|devices| devices.iter().map(MtpDeviceDesc::from).collect())
            .map_err(|e| format!("Device detection failed: {}", e))
    })
    .await
    .map_err(|e| format!("Task join error: {}", e))?
}

#[tauri::command]
pub async fn mtp_get_tracks(serial_number: String) -> Result<Vec<MtpTrack>, String> {
    let (device, _vid, _pid) = get_device(&serial_number).await?;

    let storages = device
        .storages()
        .await
        .map_err(|e| format!("Failed to get storages: {}", e))?;

    let mut tracks = Vec::new();

    for storage in &storages {
        // Walk objects manually, skipping any that fail GetObjectInfo
        // (Zune exposes abstract objects like playlists that can't be queried)
        let mut folders_to_visit: Vec<Option<mtp_rs::ObjectHandle>> = vec![None];

        while let Some(parent) = folders_to_visit.pop() {
            // Get handles in this folder
            let handles = match device
                .get_object_handles(storage.id(), parent)
                .await
            {
                Ok(h) => h,
                Err(e) => {
                    info!("Skipping folder {:?}: {}", parent, e);
                    continue;
                }
            };

            for handle in handles {
                // Try to get object info — skip on failure
                let obj = match storage.get_object_info(handle).await {
                    Ok(o) => o,
                    Err(_) => continue,
                };

                if obj.is_folder() {
                    folders_to_visit.push(Some(handle));
                    continue;
                }

                if !is_audio_format(obj.format) {
                    continue;
                }

                // Read music metadata via object properties
                let title = read_string_prop(&device, handle, OPC_NAME).await;
                let artist = read_string_prop(&device, handle, OPC_ARTIST).await;
                let album = read_string_prop(&device, handle, OPC_ALBUM_NAME).await;
                let genre = read_string_prop(&device, handle, OPC_GENRE).await;
                let track_number = read_u16_prop(&device, handle, OPC_TRACK).await;
                let duration_ms = read_u32_prop(&device, handle, OPC_DURATION).await;
                let play_count = read_u32_prop(&device, handle, OPC_USE_COUNT).await;

                tracks.push(MtpTrack {
                    handle: handle.0,
                    title: if title.is_empty() {
                        obj.filename.clone()
                    } else {
                        title
                    },
                    artist,
                    album,
                    genre,
                    track_number,
                    duration_ms,
                    play_count,
                    filename: obj.filename,
                    filesize: obj.size,
                });
            }
        }
    }

    info!("Found {} audio tracks on device", tracks.len());
    Ok(tracks)
}

#[tauri::command]
pub async fn mtp_send_track(
    event: SendTrackRequest,
    app_handle: tauri::AppHandle,
) -> Result<MtpTrack, String> {
    let (device, _vid, _pid) = get_device(&event.serial_number).await?;

    let file_path = Path::new(&event.file_path);
    let file_meta = std::fs::metadata(file_path)
        .map_err(|e| format!("Failed to read file: {}", e))?;
    let file_size = file_meta.len();

    let filename = file_path
        .file_name()
        .and_then(|f| f.to_str())
        .unwrap_or("track.mp3");

    let file_data = std::fs::read(file_path)
        .map_err(|e| format!("Failed to read file: {}", e))?;

    // Get the first storage
    let storages = device
        .storages()
        .await
        .map_err(|e| format!("Failed to get storages: {}", e))?;
    let storage = storages
        .into_iter()
        .next()
        .ok_or_else(|| "No storage found on device".to_string())?;

    // Upload to storage root — the Zune indexes tracks from the root and
    // zune-explorer also uploads to parentHandle=0. Android devices prefer
    // a Music subfolder, but Zune doesn't need one.
    let obj_info = NewObjectInfo::file(filename, file_size);

    // Create a stream from the file data
    let data_stream = stream::iter(vec![Ok::<Bytes, std::io::Error>(Bytes::from(file_data))]);

    let send_path = event.file_path.clone();
    let app = app_handle.clone();

    let handle = storage
        .upload_with_progress(None, obj_info, data_stream, move |progress: Progress| {
            let percent = progress.percent();
            let total = progress.total_bytes.unwrap_or(file_size);
            let _ = app.emit(
                "mtp-transfer-progress",
                SendTrackProgress {
                    bytes_sent: progress.bytes_transferred,
                    bytes_total: total,
                    percent,
                    file_path: send_path.clone(),
                },
            );
            ControlFlow::Continue(())
        })
        .await
        .map_err(|e| format!("Upload failed: {}", e))?;

    // Set track metadata via MTP properties. Only attempted if the device
    // supports SetObjectPropValue — Android ignores these (it reads ID3 tags
    // from the file itself), but dedicated media players like Zune need them.
    if device.supports_rename() {
        set_track_metadata(&device, handle, &event).await;
    }

    // Find album art: embedded in file tags, or a cover image in the same folder.
    let album_art = find_album_art(file_path);

    // Maintain abstract Artist/AbstractAudioAlbum objects for library grouping.
    // The Zune (and other Microsoft media devices) require these to display
    // tracks under the right artist/album in the UI; per-track string props
    // alone aren't enough. Errors are logged but don't fail the upload.
    if let Err(e) = ensure_album_grouping(
        &device,
        &storage,
        handle,
        &event.artist,
        &event.album,
        &event.serial_number,
        album_art.as_ref(),
    )
    .await
    {
        info!("Album grouping failed (track was uploaded but won't appear in library view): {}", e);
    }

    let result = MtpTrack {
        handle: handle.0,
        title: event.title,
        artist: event.artist,
        album: event.album,
        genre: event.genre,
        track_number: event.track_number,
        duration_ms: event.duration_ms,
        play_count: 0,
        filename: filename.to_string(),
        filesize: file_size,
    };

    info!("Track sent successfully: handle={}", result.handle);
    Ok(result)
}

/// Cleanly close the MTP session for a connected device. The Zune (and other
/// MTPZ devices) will otherwise remain in their "Syncing" state until the USB
/// cable is physically unplugged. The frontend should call this when the user
/// disconnects a device, switches devices, or before the app exits.
#[tauri::command]
pub async fn mtp_disconnect(serial_number: String) -> Result<(), String> {
    let holder = device_holder();
    let mut guard = holder.lock().await;

    // Only act if the cached connection matches the requested serial.
    let cached_serial = guard.as_ref().map(|c| c.serial.clone());
    if cached_serial.as_deref() != Some(serial_number.as_str()) {
        return Ok(());
    }

    if let Some(conn) = guard.as_ref() {
        // Send CloseSession (0x1003) directly via the low-level session API.
        // We can't call MtpDevice::close() because it consumes self and our
        // Arc<MtpDevice> has multiple cloned references in the cache.
        let session = conn.device.session();
        let close_op = mtp_rs::ptp::OperationCode::CloseSession;
        if let Err(e) = session.execute(close_op, &[]).await {
            info!("CloseSession failed (ignoring): {}", e);
        } else {
            info!("MTP session closed for {}", serial_number);
        }
    }

    // Drop the cached connection so the next access reopens the device.
    *guard = None;
    Ok(())
}

/// After a track is uploaded, ensure that abstract Artist + AbstractAudioAlbum
/// objects exist for it on the device, link the new track to them, and re-issue
/// SetObjectReferences so the album's track list is current. Without this, the
/// Zune UI shows tracks as "Unknown Artist" / "Unknown Album" even though the
/// per-track string properties are set correctly — the device's library view
/// is keyed off the abstract album/artist objects, not off the track props.
///
/// This mirrors NiceBeard's `_createAlbumObjects` flow but happens incrementally
/// (per track upload) instead of in a batch at the end of the sync.
async fn ensure_album_grouping(
    device: &MtpDevice,
    storage: &mtp_rs::mtp::Storage,
    track_handle: ObjectHandle,
    artist_name: &str,
    album_name: &str,
    serial: &str,
    album_art: Option<&AlbumArt>,
) -> Result<(), String> {
    // Skip if either is empty/Unknown — there's nothing meaningful to group by.
    if artist_name.is_empty() || album_name.is_empty() {
        return Ok(());
    }

    let session = device.session();
    let storage_id = storage.id();

    // Note: Artist objects (0xB218) are NOT created — the Zune rejects
    // SendObjectInfo for that format with InvalidObjectFormatCode (0x2016).
    // zune-explorer also fails to create them (confirmed via wire logs).
    // The Zune's library view works with just the AbstractAudioAlbum object
    // plus its Name, Artist string, and track references.

    // ── 1. Get-or-create the AbstractAudioAlbum object ────────────────
    let group_key = format!("{}|||{}", artist_name, album_name);

    let (album_handle, all_track_handles) = {
        let holder = device_holder();
        let mut guard = holder.lock().await;
        let conn = guard
            .as_mut()
            .filter(|c| c.serial == serial)
            .ok_or_else(|| "Cached device connection missing".to_string())?;

        if let Some(group) = conn.album_groups.get_mut(&group_key) {
            // Existing album — append the new track.
            group.track_handles.push(track_handle);
            (group.album_handle, group.track_handles.clone())
        } else {
            // Need to create the album. Drop the lock before slow ops.
            drop(guard);

            let album_filename = format!("{}--{}.alb", artist_name, album_name);
            let album_handle = send_abstract_object(
                session,
                storage_id,
                ObjectHandle(0),
                OFC_ABSTRACT_AUDIO_ALBUM,
                &album_filename,
            )
            .await
            .map_err(|e| format!("Failed to create Album object: {}", e))?;

            // Set Name + Artist string on the album.
            if let Err(e) = session
                .set_object_prop_value(album_handle, OPC_NAME, &pack_string(album_name))
                .await
            {
                info!("Could not set album Name: {}", e);
            }
            if let Err(e) = session
                .set_object_prop_value(album_handle, OPC_ARTIST, &pack_string(artist_name))
                .await
            {
                info!("Could not set album Artist: {}", e);
            }

            // Set album art if available. The Zune reads RepresentativeSampleData
            // on the AbstractAudioAlbum object for the library/album art view.
            if let Some(art) = album_art {
                // MTP byte array: 4-byte LE length prefix + raw bytes
                let mut payload = Vec::with_capacity(4 + art.data.len());
                payload.extend_from_slice(&(art.data.len() as u32).to_le_bytes());
                payload.extend_from_slice(&art.data);

                if let Err(e) = session
                    .set_object_prop_value(album_handle, OPC_REP_SAMPLE_DATA, &payload)
                    .await
                {
                    info!("Could not set album art data: {}", e);
                }

                // Format = JPEG (0x3801)
                if let Err(e) = session
                    .set_object_prop_value(
                        album_handle,
                        OPC_REP_SAMPLE_FORMAT,
                        &0x3801u16.to_le_bytes(),
                    )
                    .await
                {
                    info!("Could not set album art format: {}", e);
                }

                info!(
                    "Set album art on \"{}\" ({} bytes)",
                    album_name,
                    art.data.len(),
                );
            }

            // Insert the new group into the cache.
            let holder = device_holder();
            let mut guard = holder.lock().await;
            if let Some(conn) = guard.as_mut().filter(|c| c.serial == serial) {
                conn.album_groups.insert(
                    group_key.clone(),
                    AlbumGroup {
                        artist_handle: ObjectHandle(0),
                        album_handle,
                        track_handles: vec![track_handle],
                    },
                );
            }

            info!(
                "Created AbstractAudioAlbum \"{}\" by \"{}\" handle={}",
                album_name, artist_name, album_handle.0
            );

            (album_handle, vec![track_handle])
        }
    };

    // ── 2. Update SetObjectReferences on the album to include all tracks ──
    // The Zune library view scans these references to populate the album.
    // We re-issue this on every new track because we don't know in advance
    // when the user will stop adding to this album.
    if let Err(e) = send_set_object_references(session, album_handle, &all_track_handles).await {
        info!("Could not set object references for album: {}", e);
    }

    Ok(())
}

/// Album art data ready to send to a device.
struct AlbumArt {
    data: Vec<u8>,
}

/// Find album art for a track: first try embedded art in the file's tags,
/// then look for common cover art files in the same directory.
fn find_album_art(path: &Path) -> Option<AlbumArt> {
    // 1. Try embedded art
    if let Some(art) = extract_embedded_art(path) {
        return Some(art);
    }

    // 2. Try folder art (cover.jpg, folder.jpg, etc.)
    let dir = path.parent()?;
    const CANDIDATES: &[&str] = &[
        "cover.jpg",
        "cover.jpeg",
        "folder.jpg",
        "folder.jpeg",
        "front.jpg",
        "front.jpeg",
        "album.jpg",
        "album.jpeg",
        "artwork.jpg",
        "artwork.jpeg",
        "Cover.jpg",
        "Folder.jpg",
    ];

    for name in CANDIDATES {
        let art_path = dir.join(name);
        if art_path.exists() {
            if let Ok(data) = std::fs::read(&art_path) {
                info!("Using folder art: {} ({} bytes)", art_path.display(), data.len());
                return Some(AlbumArt { data });
            }
        }
    }

    // 3. Fall back to first .jpg/.jpeg in the directory
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let p = entry.path();
            if let Some(ext) = p.extension().and_then(|e| e.to_str()) {
                if ext.eq_ignore_ascii_case("jpg") || ext.eq_ignore_ascii_case("jpeg") {
                    if let Ok(data) = std::fs::read(&p) {
                        info!("Using folder art (fallback): {} ({} bytes)", p.display(), data.len());
                        return Some(AlbumArt { data });
                    }
                }
            }
        }
    }

    None
}

/// Extract embedded album art from audio file tags.
fn extract_embedded_art(path: &Path) -> Option<AlbumArt> {
    use lofty::file::TaggedFileExt;

    let tagged_file = lofty::read_from_path(path).ok()?;
    let tag = tagged_file.primary_tag()?;
    let pic = tag.pictures().first()?;
    info!(
        "Using embedded art: {} bytes, mime={:?}",
        pic.data().len(),
        pic.mime_type()
    );
    Some(AlbumArt {
        data: pic.data().to_vec(),
    })
}

/// Create an abstract (zero-data) object on the device using the standard
/// mtp-rs ObjectInfo path (19-field dataset). This is the same serialization
/// that `Storage::upload` uses for regular file transfers — and since the Zune
/// accepts it for audio files, it should work for abstract formats too.
async fn send_abstract_object(
    session: &mtp_rs::ptp::PtpSession,
    storage_id: mtp_rs::ptp::StorageId,
    parent_handle: ObjectHandle,
    object_format: u16,
    filename: &str,
) -> Result<ObjectHandle, String> {
    use mtp_rs::ptp::{pack_string, OperationCode};

    // Build an 18-field dataset matching exactly what zune-explorer produces:
    // storageId=0 in dataset (real value goes in command params only),
    // no Keywords field.
    let filename_bytes = pack_string(filename);
    let empty_string = [0x00u8];

    let fixed_size = 52;
    let total_size = fixed_size + filename_bytes.len() + empty_string.len() * 2;
    let mut buf = Vec::with_capacity(total_size);

    buf.extend_from_slice(&0u32.to_le_bytes()); // 1. StorageID = 0 (authoritative value is in cmd params)
    buf.extend_from_slice(&object_format.to_le_bytes()); // 2. ObjectFormat
    buf.extend_from_slice(&0u16.to_le_bytes()); // 3. ProtectionStatus
    buf.extend_from_slice(&0u32.to_le_bytes()); // 4. CompressedSize
    buf.extend_from_slice(&0u16.to_le_bytes()); // 5. ThumbFormat
    buf.extend_from_slice(&0u32.to_le_bytes()); // 6. ThumbCompressedSize
    buf.extend_from_slice(&0u32.to_le_bytes()); // 7. ThumbPixWidth
    buf.extend_from_slice(&0u32.to_le_bytes()); // 8. ThumbPixHeight
    buf.extend_from_slice(&0u32.to_le_bytes()); // 9. ImagePixWidth
    buf.extend_from_slice(&0u32.to_le_bytes()); // 10. ImagePixHeight
    buf.extend_from_slice(&0u32.to_le_bytes()); // 11. ImageBitDepth
    buf.extend_from_slice(&0u32.to_le_bytes()); // 12. ParentObject = 0
    buf.extend_from_slice(&0u16.to_le_bytes()); // 13. AssociationType
    buf.extend_from_slice(&0u32.to_le_bytes()); // 14. AssociationDesc
    buf.extend_from_slice(&0u32.to_le_bytes()); // 15. SequenceNumber
    buf.extend_from_slice(&filename_bytes);      // 16. Filename
    buf.extend_from_slice(&empty_string);        // 17. CreationDate (empty)
    buf.extend_from_slice(&empty_string);        // 18. ModificationDate (empty)

    info!(
        "SendObjectInfo dataset for format 0x{:04x}: {} bytes = {}",
        object_format,
        buf.len(),
        hex::encode(&buf)
    );

    let response = session
        .execute_with_send(
            OperationCode::SendObjectInfo,
            &[storage_id.0, parent_handle.0],
            &buf,
        )
        .await
        .map_err(|e| format!("SendObjectInfo failed: {}", e))?;

    let resp_code = u16::from(response.code);
    info!(
        "SendObjectInfo response: 0x{:04x} params={:?}",
        resp_code, response.params
    );
    if resp_code != 0x2001 {
        return Err(format!(
            "SendObjectInfo returned 0x{:04x} for format 0x{:04x}",
            resp_code, object_format
        ));
    }

    let new_handle_raw = *response
        .params
        .get(2)
        .ok_or_else(|| "SendObjectInfo response missing new handle param".to_string())?;
    let new_handle = ObjectHandle(new_handle_raw);

    session
        .execute_with_send(OperationCode::SendObject, &[], &[])
        .await
        .map_err(|e| format!("SendObject (empty) failed: {}", e))?;

    Ok(new_handle)
}

/// Send SetObjectReferences (PTP opcode 0x9811) directly via the low-level
/// session API. mtp-rs's high-level Storage API doesn't expose this operation,
/// so we marshal the payload ourselves.
///
/// Wire format (per MTP 1.1 §5.5.7):
///   command params: [object_handle]
///   data phase: u32 array_length, then N × u32 reference handles, all LE
async fn send_set_object_references(
    session: &mtp_rs::ptp::PtpSession,
    object_handle: ObjectHandle,
    references: &[ObjectHandle],
) -> Result<(), String> {
    use mtp_rs::ptp::OperationCode;

    let mut payload = Vec::with_capacity(4 + references.len() * 4);
    payload.extend_from_slice(&(references.len() as u32).to_le_bytes());
    for r in references {
        payload.extend_from_slice(&r.0.to_le_bytes());
    }

    session
        .execute_with_send(
            OperationCode::Unknown(0x9811),
            &[object_handle.0],
            &payload,
        )
        .await
        .map_err(|e| format!("SetObjectReferences failed: {}", e))?;

    Ok(())
}

/// Find an existing "Music" folder in the storage root, or create one.
async fn find_or_create_music_folder(
    device: &MtpDevice,
    storage: &mtp_rs::mtp::Storage,
) -> Result<ObjectHandle, String> {
    // Walk root manually, skipping any handles that fail GetObjectInfo.
    // The Zune exposes abstract objects in root (playlists etc.) that can't
    // be queried — using `storage.list_objects(None)` would fail the whole
    // call on the first such object.
    let handles = device
        .get_object_handles(storage.id(), None)
        .await
        .map_err(|e| format!("Failed to list root handles: {}", e))?;

    for handle in handles {
        let obj = match storage.get_object_info(handle).await {
            Ok(o) => o,
            Err(_) => continue,
        };
        if obj.is_folder() && obj.filename.eq_ignore_ascii_case("Music") {
            info!("Using existing Music folder: handle={}", obj.handle.0);
            return Ok(obj.handle);
        }
    }

    // None found — create one
    let handle = storage
        .create_folder(None, "Music")
        .await
        .map_err(|e| format!("Failed to create Music folder: {}", e))?;

    info!("Created Music folder: handle={}", handle.0);
    Ok(handle)
}

/// Set music metadata properties on an uploaded object.
/// Errors are logged but not propagated — metadata is best-effort.
async fn set_track_metadata(device: &MtpDevice, handle: ObjectHandle, req: &SendTrackRequest) {
    use mtp_rs::ptp::pack_string;

    let session = device.session();

    // Per-track properties only. AlbumName (0xDC9A) and AlbumArtist (0xDC9B)
    // are intentionally NOT set here — the Zune rejects those on track objects
    // with AccessDenied. They belong on the abstract AbstractAudioAlbum object,
    // which `ensure_album_grouping` creates and populates after this call.
    let props: Vec<(ObjectPropertyCode, Vec<u8>)> = vec![
        (OPC_NAME, pack_string(&req.title)),
        (OPC_ARTIST, pack_string(&req.artist)),
        (OPC_GENRE, pack_string(&req.genre)),
        (OPC_TRACK, req.track_number.to_le_bytes().to_vec()),
        (OPC_DURATION, req.duration_ms.to_le_bytes().to_vec()),
    ];

    for (prop, value) in props {
        if let Err(e) = session.set_object_prop_value(handle, prop, &value).await {
            info!("Device declined property {:?}: {}", prop, e);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::Path;

    // ── is_zune ──────────────────────────────────────────────────────────────

    #[test]
    fn is_zune_returns_true_for_all_known_zune_devices() {
        // All five known Zune VID/PID combinations must be recognized.
        assert!(is_zune(0x045E, 0x0710), "Zune (0x0710) not recognized");
        assert!(is_zune(0x045E, 0x0711), "Zune (0x0711) not recognized");
        assert!(is_zune(0x045E, 0x0712), "Zune (0x0712) not recognized");
        assert!(is_zune(0x045E, 0x063E), "Zune HD (0x063E) not recognized");
        assert!(is_zune(0x045E, 0x0714), "Zune alt (0x0714) not recognized");
    }

    #[test]
    fn is_zune_returns_false_for_non_zune_vid() {
        // Different vendor ID — not a Zune, even if PID matches.
        assert!(!is_zune(0x1234, 0x0710));
        assert!(!is_zune(0x0000, 0x0000));
    }

    #[test]
    fn is_zune_returns_false_for_wrong_pid_with_microsoft_vid() {
        // Microsoft VID but a random PID that isn't in the Zune list.
        assert!(!is_zune(0x045E, 0x0001));
        assert!(!is_zune(0x045E, 0xFFFF));
    }

    #[test]
    fn is_zune_returns_false_for_zero_vid_pid() {
        assert!(!is_zune(0x0000, 0x0000));
    }

    // ── MtpTrack struct ───────────────────────────────────────────────────────

    #[test]
    fn mtp_track_fields_are_set_correctly() {
        let track = MtpTrack {
            handle: 42,
            title: "Thriller".to_string(),
            artist: "Michael Jackson".to_string(),
            album: "Thriller".to_string(),
            genre: "Pop".to_string(),
            track_number: 1,
            duration_ms: 358_000,
            play_count: 7,
            filename: "01 - Thriller.mp3".to_string(),
            filesize: 1_234_567,
        };

        assert_eq!(track.handle, 42);
        assert_eq!(track.title, "Thriller");
        assert_eq!(track.artist, "Michael Jackson");
        assert_eq!(track.album, "Thriller");
        assert_eq!(track.genre, "Pop");
        assert_eq!(track.track_number, 1);
        assert_eq!(track.duration_ms, 358_000);
        assert_eq!(track.play_count, 7);
        assert_eq!(track.filename, "01 - Thriller.mp3");
        assert_eq!(track.filesize, 1_234_567);
    }

    #[test]
    fn mtp_track_serializes_to_camel_case_json() {
        let track = MtpTrack {
            handle: 10,
            title: "Song".to_string(),
            artist: "Artist".to_string(),
            album: "Album".to_string(),
            genre: "Rock".to_string(),
            track_number: 3,
            duration_ms: 210_000,
            play_count: 0,
            filename: "song.mp3".to_string(),
            filesize: 5_000_000,
        };

        let json = serde_json::to_string(&track).expect("serialization failed");
        // serde(rename_all = "camelCase") must produce camelCase keys.
        assert!(json.contains("\"trackNumber\""), "trackNumber key not found in: {}", json);
        assert!(json.contains("\"durationMs\""), "durationMs key not found in: {}", json);
        assert!(json.contains("\"playCount\""), "playCount key not found in: {}", json);
        assert!(json.contains("\"filesize\""), "filesize key not found in: {}", json);
    }

    #[test]
    fn mtp_track_zero_play_count_serializes_correctly() {
        let track = MtpTrack {
            handle: 1,
            title: "New Track".to_string(),
            artist: "".to_string(),
            album: "".to_string(),
            genre: "".to_string(),
            track_number: 0,
            duration_ms: 0,
            play_count: 0,
            filename: "new.mp3".to_string(),
            filesize: 0,
        };
        let json = serde_json::to_string(&track).expect("serialization failed");
        assert!(json.contains("\"playCount\":0"));
    }

    // ── MtpDeviceDesc struct ──────────────────────────────────────────────────

    #[test]
    fn mtp_device_desc_serializes_to_camel_case_json() {
        let desc = MtpDeviceDesc {
            vendor_id: 0x045E,
            product_id: 0x0710,
            manufacturer: "Microsoft".to_string(),
            product: "Zune".to_string(),
            serial_number: "ZUNE001".to_string(),
        };

        let json = serde_json::to_string(&desc).expect("serialization failed");
        assert!(json.contains("\"vendorId\""), "vendorId not in: {}", json);
        assert!(json.contains("\"productId\""), "productId not in: {}", json);
        assert!(json.contains("\"serialNumber\""), "serialNumber not in: {}", json);
        assert!(json.contains("\"manufacturer\""), "manufacturer not in: {}", json);
        assert!(json.contains("\"product\""), "product not in: {}", json);
    }

    #[test]
    fn mtp_device_desc_roundtrips_through_json() {
        let original = MtpDeviceDesc {
            vendor_id: 0x045E,
            product_id: 0x0712,
            manufacturer: "Microsoft Corp.".to_string(),
            product: "Zune 30GB".to_string(),
            serial_number: "SN-12345".to_string(),
        };
        let json = serde_json::to_string(&original).expect("serialize failed");
        let decoded: MtpDeviceDesc = serde_json::from_str(&json).expect("deserialize failed");
        assert_eq!(decoded.vendor_id, original.vendor_id);
        assert_eq!(decoded.product_id, original.product_id);
        assert_eq!(decoded.manufacturer, original.manufacturer);
        assert_eq!(decoded.product, original.product);
        assert_eq!(decoded.serial_number, original.serial_number);
    }

    // ── SendTrackRequest ──────────────────────────────────────────────────────

    #[test]
    fn send_track_request_serializes_to_camel_case() {
        let req = SendTrackRequest {
            file_path: "/music/song.mp3".to_string(),
            title: "Hello".to_string(),
            artist: "Adele".to_string(),
            album: "25".to_string(),
            genre: "Pop".to_string(),
            track_number: 1,
            duration_ms: 295_000,
            serial_number: "SN-001".to_string(),
        };
        let json = serde_json::to_string(&req).expect("serialize failed");
        assert!(json.contains("\"filePath\""), "filePath not in: {}", json);
        assert!(json.contains("\"trackNumber\""), "trackNumber not in: {}", json);
        assert!(json.contains("\"durationMs\""), "durationMs not in: {}", json);
        assert!(json.contains("\"serialNumber\""), "serialNumber not in: {}", json);
    }

    // ── SendTrackProgress ─────────────────────────────────────────────────────

    #[test]
    fn send_track_progress_serializes_to_camel_case() {
        let progress = SendTrackProgress {
            bytes_sent: 1024,
            bytes_total: 4096,
            percent: 25.0,
            file_path: "/music/song.mp3".to_string(),
        };
        let json = serde_json::to_string(&progress).expect("serialize failed");
        assert!(json.contains("\"bytesSent\""), "bytesSent not in: {}", json);
        assert!(json.contains("\"bytesTotal\""), "bytesTotal not in: {}", json);
        assert!(json.contains("\"filePath\""), "filePath not in: {}", json);
    }

    // ── find_album_art (filesystem) ───────────────────────────────────────────

    #[test]
    fn find_album_art_returns_none_for_nonexistent_path() {
        // A path that doesn't exist has no art (no parent dir to search).
        let path = Path::new("/nonexistent/music/song.mp3");
        // find_album_art tries to read the parent dir; on a nonexistent path
        // it returns None rather than panicking.
        let result = find_album_art(path);
        assert!(result.is_none());
    }

    #[test]
    fn find_album_art_finds_cover_jpg_in_same_directory() {
        let dir = tempfile::tempdir().expect("tmpdir failed");
        let cover_path = dir.path().join("cover.jpg");
        let song_path = dir.path().join("song.mp3");

        // Write a fake JPEG (just some bytes).
        fs::write(&cover_path, b"\xff\xd8\xff\xe0fake jpeg data").expect("write cover failed");
        // Create the song file (contents don't matter for this test).
        fs::write(&song_path, b"ID3 fake mp3").expect("write song failed");

        let result = find_album_art(&song_path);
        assert!(result.is_some(), "expected Some(AlbumArt) for cover.jpg");
        let art = result.unwrap();
        assert_eq!(art.data, b"\xff\xd8\xff\xe0fake jpeg data");
    }

    #[test]
    fn find_album_art_finds_folder_jpg_when_no_cover() {
        let dir = tempfile::tempdir().expect("tmpdir failed");
        let folder_path = dir.path().join("folder.jpg");
        let song_path = dir.path().join("song.mp3");

        fs::write(&folder_path, b"folder-art-data").expect("write folder.jpg failed");
        fs::write(&song_path, b"ID3 fake mp3").expect("write song failed");

        let result = find_album_art(&song_path);
        assert!(result.is_some(), "expected Some(AlbumArt) for folder.jpg");
        let art = result.unwrap();
        assert_eq!(art.data, b"folder-art-data");
    }

    #[test]
    fn find_album_art_prefers_cover_jpg_over_folder_jpg() {
        let dir = tempfile::tempdir().expect("tmpdir failed");
        let cover_path = dir.path().join("cover.jpg");
        let folder_path = dir.path().join("folder.jpg");
        let song_path = dir.path().join("song.mp3");

        // cover.jpg is listed first in CANDIDATES so it takes priority.
        fs::write(&cover_path, b"cover-data").expect("write cover failed");
        fs::write(&folder_path, b"folder-data").expect("write folder failed");
        fs::write(&song_path, b"ID3 fake").expect("write song failed");

        let result = find_album_art(&song_path);
        assert!(result.is_some());
        assert_eq!(result.unwrap().data, b"cover-data");
    }

    #[test]
    fn find_album_art_returns_none_when_no_art_files_exist() {
        let dir = tempfile::tempdir().expect("tmpdir failed");
        let song_path = dir.path().join("song.mp3");
        fs::write(&song_path, b"ID3 fake").expect("write song failed");

        let result = find_album_art(&song_path);
        assert!(result.is_none(), "expected None when no art files present");
    }

    #[test]
    fn find_album_art_falls_back_to_any_jpeg_in_directory() {
        let dir = tempfile::tempdir().expect("tmpdir failed");
        // Use an unusual name that isn't in CANDIDATES list.
        let art_path = dir.path().join("disc1_cover_scan.jpg");
        let song_path = dir.path().join("song.mp3");

        fs::write(&art_path, b"fallback-art").expect("write art failed");
        fs::write(&song_path, b"ID3 fake").expect("write song failed");

        let result = find_album_art(&song_path);
        assert!(result.is_some(), "expected fallback art found via directory scan");
    }
}
