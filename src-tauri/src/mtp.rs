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
    unpack_string, unpack_u16, unpack_u32, ObjectFormatCode, ObjectHandle, ObjectPropertyCode,
};
use mtp_rs::Progress;
use serde::{Deserialize, Serialize};
use std::ops::ControlFlow;
use std::path::Path;
use std::sync::Arc;
use tauri::Emitter;
use tokio::sync::Mutex;

use crate::mtpz;

// ─── Standard MTP object property codes for music metadata ────────────────
// See MTP spec §5.3.12 — these work on any compliant MTP device.

/// Artist name (string)
const OPC_ARTIST: ObjectPropertyCode = ObjectPropertyCode::Unknown(0xDC46);
/// Album name (string)
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

/// Holds an open MTP device connection so we don't re-open for every command.
struct DeviceConnection {
    device: MtpDevice,
    serial: String,
}

// We use a simple mutex-guarded Option for connection caching.
static DEVICE: std::sync::OnceLock<Arc<Mutex<Option<DeviceConnection>>>> = std::sync::OnceLock::new();

fn device_holder() -> &'static Arc<Mutex<Option<DeviceConnection>>> {
    DEVICE.get_or_init(|| Arc::new(Mutex::new(None)))
}

/// Get or open a device connection by serial number.
async fn get_device(serial: &str) -> Result<MtpDevice, String> {
    let holder = device_holder();
    let mut guard = holder.lock().await;

    // Reuse existing connection if same device
    if let Some(conn) = guard.as_ref() {
        if conn.serial == serial {
            return Ok(conn.device.clone());
        }
    }

    // Open new connection
    let device = MtpDevice::open_by_serial(serial)
        .await
        .map_err(|e| format!("Failed to open device: {}", e))?;

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
    });

    Ok(device)
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
        MtpDevice::list_devices()
            .map(|devices| devices.iter().map(MtpDeviceDesc::from).collect())
            .map_err(|e| format!("Device detection failed: {}", e))
    })
    .await
    .map_err(|e| format!("Task join error: {}", e))?
}

#[tauri::command]
pub async fn mtp_get_tracks(serial_number: String) -> Result<Vec<MtpTrack>, String> {
    let device = get_device(&serial_number).await?;

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
    let device = get_device(&event.serial_number).await?;

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

    // Find or create a Music folder to upload into.
    // Many devices (especially Android) reject uploads to the storage root.
    let music_folder = find_or_create_music_folder(&storage).await?;

    let obj_info = NewObjectInfo::file(filename, file_size);

    // Create a stream from the file data
    let data_stream = stream::iter(vec![Ok::<Bytes, std::io::Error>(Bytes::from(file_data))]);

    let send_path = event.file_path.clone();
    let app = app_handle.clone();

    let handle = storage
        .upload_with_progress(Some(music_folder), obj_info, data_stream, move |progress: Progress| {
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

/// Find an existing "Music" folder in the storage root, or create one.
async fn find_or_create_music_folder(
    storage: &mtp_rs::mtp::Storage,
) -> Result<ObjectHandle, String> {
    let root_objects = storage
        .list_objects(None)
        .await
        .map_err(|e| format!("Failed to list root objects: {}", e))?;

    // Look for an existing Music folder (case-insensitive)
    for obj in &root_objects {
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

    let props: Vec<(ObjectPropertyCode, Vec<u8>)> = vec![
        (OPC_NAME, pack_string(&req.title)),
        (OPC_ARTIST, pack_string(&req.artist)),
        (OPC_ALBUM_NAME, pack_string(&req.album)),
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
