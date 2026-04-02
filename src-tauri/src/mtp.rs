// mtp.rs - Zune MTP sync proof-of-concept
//
// Minimal FFI bindings to libmtp for device detection, file transfer,
// and play count extraction. Intended for use with libmtp-zune fork
// (https://github.com/kbhomes/libmtp-zune) which adds Zune device support.
//
// Requires libmtp (or libmtp-zune) installed on the system:
//   - Linux: `apt install libmtp-dev` or build libmtp-zune from source
//   - The library must be in the linker search path

use log::{error, info};
use serde::{Deserialize, Serialize};
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int, c_uint};
use std::ptr;
use tauri::Emitter;

// ─── libmtp FFI declarations ───────────────────────────────────────────────

// Opaque device handle
#[repr(C)]
pub struct LIBMTP_mtpdevice_t {
    _private: [u8; 0],
}

#[repr(C)]
#[derive(Debug)]
pub struct LIBMTP_raw_device_t {
    pub device_entry: LIBMTP_device_entry_t,
    pub bus_location: u32,
    pub devnum: u8,
}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct LIBMTP_device_entry_t {
    pub vendor: *mut c_char,
    pub vendor_id: u16,
    pub product: *mut c_char,
    pub product_id: u16,
    pub device_flags: u32,
}

#[repr(C)]
pub struct LIBMTP_track_t {
    pub item_id: u32,
    pub parent_id: u32,
    pub storage_id: u32,
    pub title: *mut c_char,
    pub artist: *mut c_char,
    pub composer: *mut c_char,
    pub genre: *mut c_char,
    pub album: *mut c_char,
    pub date: *mut c_char,
    pub filename: *mut c_char,
    pub tracknumber: u16,
    pub duration: u32,       // milliseconds
    pub samplerate: u32,
    pub nochannels: u16,
    pub wavecodec: u32,
    pub bitrate: u32,
    pub bitratetype: u16,
    pub rating: u16,
    pub usecount: u32,       // <-- this is the play count
    pub filesize: u64,
    pub modificationdate: i64,
    pub filetype: c_int,
    pub next: *mut LIBMTP_track_t,
}

#[repr(C)]
pub struct LIBMTP_album_t {
    pub album_id: u32,
    pub parent_id: u32,
    pub storage_id: u32,
    pub name: *mut c_char,
    pub artist: *mut c_char,
    pub composer: *mut c_char,
    pub genre: *mut c_char,
    pub tracks: *mut u32,
    pub no_tracks: u32,
    pub next: *mut LIBMTP_album_t,
}

// Callback type for progress reporting
pub type LIBMTP_progressfunc_t =
    Option<unsafe extern "C" fn(sent: u64, total: u64, data: *const std::ffi::c_void) -> c_int>;

// File type constants
pub const LIBMTP_FILETYPE_MP3: c_int = 0;
pub const LIBMTP_FILETYPE_WMA: c_int = 3;

#[repr(C)]
#[derive(Debug)]
pub enum LIBMTP_error_number_t {
    LIBMTP_ERROR_NONE = 0,
    LIBMTP_ERROR_GENERAL = 1,
    LIBMTP_ERROR_PTP_LAYER = 2,
    LIBMTP_ERROR_USB_LAYER = 3,
    LIBMTP_ERROR_MEMORY_ALLOCATION = 4,
    LIBMTP_ERROR_NO_DEVICE_ATTACHED = 5,
    LIBMTP_ERROR_STORAGE_FULL = 6,
    LIBMTP_ERROR_CONNECTING = 7,
    LIBMTP_ERROR_CANCELLED = 8,
}

extern "C" {
    fn LIBMTP_Init();
    fn LIBMTP_Detect_Raw_Devices(
        devices: *mut *mut LIBMTP_raw_device_t,
        numdevs: *mut c_int,
    ) -> c_int;
    fn LIBMTP_Open_Raw_Device_Uncached(rawdevice: *mut LIBMTP_raw_device_t)
        -> *mut LIBMTP_mtpdevice_t;
    fn LIBMTP_Release_Device(device: *mut LIBMTP_mtpdevice_t);
    fn LIBMTP_Get_Friendlyname(device: *mut LIBMTP_mtpdevice_t) -> *mut c_char;
    fn LIBMTP_Get_Modelname(device: *mut LIBMTP_mtpdevice_t) -> *mut c_char;
    fn LIBMTP_Get_Serialnumber(device: *mut LIBMTP_mtpdevice_t) -> *mut c_char;
    fn LIBMTP_Get_Tracklisting_With_Callback(
        device: *mut LIBMTP_mtpdevice_t,
        callback: LIBMTP_progressfunc_t,
        data: *const std::ffi::c_void,
    ) -> *mut LIBMTP_track_t;
    fn LIBMTP_Send_Track_From_File(
        device: *mut LIBMTP_mtpdevice_t,
        path: *const c_char,
        metadata: *mut LIBMTP_track_t,
        callback: LIBMTP_progressfunc_t,
        data: *const std::ffi::c_void,
    ) -> c_int;
    fn LIBMTP_Get_Albumlist(device: *mut LIBMTP_mtpdevice_t) -> *mut LIBMTP_album_t;
    fn LIBMTP_Create_New_Album(
        device: *mut LIBMTP_mtpdevice_t,
        album: *mut LIBMTP_album_t,
    ) -> c_int;
    fn LIBMTP_Update_Album(
        device: *mut LIBMTP_mtpdevice_t,
        album: *mut LIBMTP_album_t,
    ) -> c_int;
    fn LIBMTP_destroy_track_t(track: *mut LIBMTP_track_t);
    fn LIBMTP_destroy_album_t(album: *mut LIBMTP_album_t);
    fn LIBMTP_Get_Storage(
        device: *mut LIBMTP_mtpdevice_t,
        sortby: c_int,
    ) -> c_int;
    fn free(ptr: *mut std::ffi::c_void);
}

// ─── Safe Rust wrappers ────────────────────────────────────────────────────

/// Initialize libmtp (call once at startup)
fn mtp_init() {
    unsafe { LIBMTP_Init() };
}

/// Read a C string pointer, returning empty string for null
unsafe fn read_c_str(ptr: *mut c_char) -> String {
    if ptr.is_null() {
        String::new()
    } else {
        let s = CStr::from_ptr(ptr).to_string_lossy().into_owned();
        free(ptr as *mut std::ffi::c_void);
        s
    }
}

/// Read a C string pointer without freeing it
unsafe fn peek_c_str(ptr: *const c_char) -> String {
    if ptr.is_null() {
        String::new()
    } else {
        CStr::from_ptr(ptr).to_string_lossy().into_owned()
    }
}

// ─── Data types for Tauri serialization ────────────────────────────────────

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct MtpDevice {
    pub vendor: String,
    pub vendor_id: u16,
    pub product: String,
    pub product_id: u16,
    pub bus_location: u32,
    pub dev_num: u8,
    pub friendly_name: String,
    pub model_name: String,
    pub serial_number: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct MtpTrack {
    pub item_id: u32,
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
    pub device_index: usize,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct SendTrackProgress {
    pub bytes_sent: u64,
    pub bytes_total: u64,
    pub percent: f64,
    pub file_path: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "camelCase")]
pub struct MtpDetectRequest {}

// ─── Progress callback plumbing ────────────────────────────────────────────

struct ProgressCallbackData {
    app_handle: tauri::AppHandle,
    file_path: String,
}

unsafe extern "C" fn transfer_progress_cb(
    sent: u64,
    total: u64,
    data: *const std::ffi::c_void,
) -> c_int {
    if !data.is_null() {
        let cb_data = &*(data as *const ProgressCallbackData);
        let percent = if total > 0 {
            (sent as f64 / total as f64) * 100.0
        } else {
            0.0
        };
        let _ = cb_data.app_handle.emit(
            "mtp-transfer-progress",
            SendTrackProgress {
                bytes_sent: sent,
                bytes_total: total,
                percent,
                file_path: cb_data.file_path.clone(),
            },
        );
    }
    0 // return 0 to continue
}

// ─── Core operations ───────────────────────────────────────────────────────

/// Detect connected MTP devices. Opens each briefly to read names.
fn detect_devices_inner() -> Result<Vec<MtpDevice>, String> {
    mtp_init();

    let mut raw_devices: *mut LIBMTP_raw_device_t = ptr::null_mut();
    let mut num_devices: c_int = 0;

    let err = unsafe { LIBMTP_Detect_Raw_Devices(&mut raw_devices, &mut num_devices) };

    if err != 0 || num_devices == 0 {
        if !raw_devices.is_null() {
            unsafe { free(raw_devices as *mut std::ffi::c_void) };
        }
        return if err == 5 {
            Ok(vec![]) // NO_DEVICE_ATTACHED
        } else if err != 0 {
            Err(format!("LIBMTP_Detect_Raw_Devices failed with error code {}", err))
        } else {
            Ok(vec![])
        };
    }

    let mut devices = Vec::new();
    for i in 0..num_devices as isize {
        let raw = unsafe { &mut *raw_devices.offset(i) };

        // Open device to get friendly name, model, serial
        let dev_ptr = unsafe { LIBMTP_Open_Raw_Device_Uncached(raw) };
        let (friendly_name, model_name, serial_number) = if !dev_ptr.is_null() {
            let f = unsafe { read_c_str(LIBMTP_Get_Friendlyname(dev_ptr)) };
            let m = unsafe { read_c_str(LIBMTP_Get_Modelname(dev_ptr)) };
            let s = unsafe { read_c_str(LIBMTP_Get_Serialnumber(dev_ptr)) };
            unsafe { LIBMTP_Release_Device(dev_ptr) };
            (f, m, s)
        } else {
            (String::new(), String::new(), String::new())
        };

        let vendor = unsafe { peek_c_str(raw.device_entry.vendor) };
        let product = unsafe { peek_c_str(raw.device_entry.product) };

        devices.push(MtpDevice {
            vendor,
            vendor_id: raw.device_entry.vendor_id,
            product,
            product_id: raw.device_entry.product_id,
            bus_location: raw.bus_location,
            dev_num: raw.devnum,
            friendly_name,
            model_name,
            serial_number,
        });
    }

    unsafe { free(raw_devices as *mut std::ffi::c_void) };
    Ok(devices)
}

/// Open the Nth raw device (helper for other operations)
fn open_device(device_index: usize) -> Result<*mut LIBMTP_mtpdevice_t, String> {
    mtp_init();

    let mut raw_devices: *mut LIBMTP_raw_device_t = ptr::null_mut();
    let mut num_devices: c_int = 0;

    let err = unsafe { LIBMTP_Detect_Raw_Devices(&mut raw_devices, &mut num_devices) };
    if err != 0 || num_devices == 0 {
        if !raw_devices.is_null() {
            unsafe { free(raw_devices as *mut std::ffi::c_void) };
        }
        return Err("No MTP devices found".to_string());
    }

    if device_index >= num_devices as usize {
        unsafe { free(raw_devices as *mut std::ffi::c_void) };
        return Err(format!(
            "Device index {} out of range (found {} devices)",
            device_index, num_devices
        ));
    }

    let raw = unsafe { &mut *raw_devices.offset(device_index as isize) };
    let dev = unsafe { LIBMTP_Open_Raw_Device_Uncached(raw) };

    // Note: we intentionally do NOT free raw_devices here because the device
    // handle may reference it internally. The caller must release the device.
    // In practice for a PoC this is acceptable; a production version would
    // manage lifetimes more carefully.

    if dev.is_null() {
        Err("Failed to open MTP device".to_string())
    } else {
        // Fetch storage info so transfers work
        unsafe { LIBMTP_Get_Storage(dev, 0) };
        Ok(dev)
    }
}

/// Get all tracks from the device with play counts
fn get_tracks_inner(device_index: usize) -> Result<Vec<MtpTrack>, String> {
    let dev = open_device(device_index)?;

    let track_list = unsafe {
        LIBMTP_Get_Tracklisting_With_Callback(dev, None, ptr::null())
    };

    let mut tracks = Vec::new();
    let mut current = track_list;
    while !current.is_null() {
        let t = unsafe { &*current };
        tracks.push(MtpTrack {
            item_id: t.item_id,
            title: unsafe { peek_c_str(t.title) },
            artist: unsafe { peek_c_str(t.artist) },
            album: unsafe { peek_c_str(t.album) },
            genre: unsafe { peek_c_str(t.genre) },
            track_number: t.tracknumber,
            duration_ms: t.duration,
            play_count: t.usecount,
            filename: unsafe { peek_c_str(t.filename) },
            filesize: t.filesize,
        });
        current = t.next;
    }

    // Free the linked list
    let mut current = track_list;
    while !current.is_null() {
        let next = unsafe { (*current).next };
        unsafe { LIBMTP_destroy_track_t(current) };
        current = next;
    }

    unsafe { LIBMTP_Release_Device(dev) };
    Ok(tracks)
}

/// Send an MP3 file to the device
fn send_track_inner(
    req: &SendTrackRequest,
    app_handle: &tauri::AppHandle,
) -> Result<MtpTrack, String> {
    let dev = open_device(req.device_index)?;

    // Get file size
    let file_meta = std::fs::metadata(&req.file_path)
        .map_err(|e| format!("Failed to read file: {}", e))?;

    let c_path = CString::new(req.file_path.as_str())
        .map_err(|_| "Invalid file path")?;
    let c_title = CString::new(req.title.as_str()).unwrap_or_default();
    let c_artist = CString::new(req.artist.as_str()).unwrap_or_default();
    let c_album = CString::new(req.album.as_str()).unwrap_or_default();
    let c_genre = CString::new(req.genre.as_str()).unwrap_or_default();
    let c_filename = CString::new(
        std::path::Path::new(&req.file_path)
            .file_name()
            .and_then(|f| f.to_str())
            .unwrap_or("track.mp3"),
    )
    .unwrap_or_default();

    // Determine file type from extension
    let filetype = if req.file_path.to_lowercase().ends_with(".wma") {
        LIBMTP_FILETYPE_WMA
    } else {
        LIBMTP_FILETYPE_MP3
    };

    // Build track metadata struct
    let mut track = LIBMTP_track_t {
        item_id: 0,
        parent_id: 0,
        storage_id: 0,
        title: c_title.as_ptr() as *mut c_char,
        artist: c_artist.as_ptr() as *mut c_char,
        composer: ptr::null_mut(),
        genre: c_genre.as_ptr() as *mut c_char,
        album: c_album.as_ptr() as *mut c_char,
        date: ptr::null_mut(),
        filename: c_filename.as_ptr() as *mut c_char,
        tracknumber: req.track_number,
        duration: req.duration_ms,
        samplerate: 0,
        nochannels: 0,
        wavecodec: 0,
        bitrate: 0,
        bitratetype: 0,
        rating: 0,
        usecount: 0,
        filesize: file_meta.len(),
        modificationdate: 0,
        filetype,
        next: ptr::null_mut(),
    };

    let cb_data = ProgressCallbackData {
        app_handle: app_handle.clone(),
        file_path: req.file_path.clone(),
    };

    let ret = unsafe {
        LIBMTP_Send_Track_From_File(
            dev,
            c_path.as_ptr(),
            &mut track,
            Some(transfer_progress_cb),
            &cb_data as *const ProgressCallbackData as *const std::ffi::c_void,
        )
    };

    if ret != 0 {
        unsafe { LIBMTP_Release_Device(dev) };
        return Err(format!("LIBMTP_Send_Track_From_File failed (error {})", ret));
    }

    // Optionally create/update album object (required for Zune to show album info)
    create_or_update_album(dev, &req.album, &req.artist, track.item_id);

    let result = MtpTrack {
        item_id: track.item_id,
        title: req.title.clone(),
        artist: req.artist.clone(),
        album: req.album.clone(),
        genre: req.genre.clone(),
        track_number: req.track_number,
        duration_ms: req.duration_ms,
        play_count: 0,
        filename: c_filename.to_str().unwrap_or("").to_string(),
        filesize: file_meta.len(),
    };

    unsafe { LIBMTP_Release_Device(dev) };

    info!("Track sent successfully: item_id={}", result.item_id);
    Ok(result)
}

/// Create or update an album object on the device.
/// Zune devices require abstract album objects paired with tracks to display
/// album information correctly.
fn create_or_update_album(
    dev: *mut LIBMTP_mtpdevice_t,
    album_name: &str,
    artist_name: &str,
    track_id: u32,
) {
    let album_list = unsafe { LIBMTP_Get_Albumlist(dev) };

    // Search for existing album
    let mut found_album: *mut LIBMTP_album_t = ptr::null_mut();
    let mut current = album_list;
    while !current.is_null() {
        let a = unsafe { &*current };
        let name = unsafe { peek_c_str(a.name) };
        if name == album_name {
            found_album = current;
            break;
        }
        current = unsafe { (*current).next };
    }

    if !found_album.is_null() {
        // Add track to existing album
        let a = unsafe { &mut *found_album };
        let old_count = a.no_tracks as usize;

        // Build new track ID array with the additional track
        let mut track_ids: Vec<u32> = if !a.tracks.is_null() && old_count > 0 {
            unsafe { std::slice::from_raw_parts(a.tracks, old_count).to_vec() }
        } else {
            Vec::new()
        };

        // Don't add duplicate
        if !track_ids.contains(&track_id) {
            track_ids.push(track_id);
            a.tracks = track_ids.as_mut_ptr();
            a.no_tracks = track_ids.len() as u32;

            let ret = unsafe { LIBMTP_Update_Album(dev, found_album) };
            if ret != 0 {
                error!("Failed to update album '{}'", album_name);
            } else {
                info!("Updated album '{}' with track {}", album_name, track_id);
            }
            std::mem::forget(track_ids); // don't drop, libmtp may reference it
        }
    } else {
        // Create new album
        let c_name = CString::new(album_name).unwrap_or_default();
        let c_artist = CString::new(artist_name).unwrap_or_default();
        let mut track_ids = vec![track_id];

        let mut new_album = LIBMTP_album_t {
            album_id: 0,
            parent_id: 0,
            storage_id: 0,
            name: c_name.as_ptr() as *mut c_char,
            artist: c_artist.as_ptr() as *mut c_char,
            composer: ptr::null_mut(),
            genre: ptr::null_mut(),
            tracks: track_ids.as_mut_ptr(),
            no_tracks: 1,
            next: ptr::null_mut(),
        };

        let ret = unsafe { LIBMTP_Create_New_Album(dev, &mut new_album) };
        if ret != 0 {
            error!("Failed to create album '{}'", album_name);
        } else {
            info!(
                "Created album '{}' (id={}) with track {}",
                album_name, new_album.album_id, track_id
            );
        }
        std::mem::forget(track_ids);
    }

    // Free album list
    let mut current = album_list;
    while !current.is_null() {
        let next = unsafe { (*current).next };
        unsafe { LIBMTP_destroy_album_t(current) };
        current = next;
    }
}

// ─── Tauri commands ────────────────────────────────────────────────────────

#[tauri::command]
pub async fn mtp_detect_devices() -> Result<Vec<MtpDevice>, String> {
    // Run on blocking thread since libmtp does synchronous USB I/O
    tokio::task::spawn_blocking(|| detect_devices_inner())
        .await
        .map_err(|e| format!("Task join error: {}", e))?
}

#[tauri::command]
pub async fn mtp_get_tracks(device_index: usize) -> Result<Vec<MtpTrack>, String> {
    tokio::task::spawn_blocking(move || get_tracks_inner(device_index))
        .await
        .map_err(|e| format!("Task join error: {}", e))?
}

#[tauri::command]
pub async fn mtp_send_track(
    event: SendTrackRequest,
    app_handle: tauri::AppHandle,
) -> Result<MtpTrack, String> {
    tokio::task::spawn_blocking(move || send_track_inner(&event, &app_handle))
        .await
        .map_err(|e| format!("Task join error: {}", e))?
}
