<script lang="ts">
    import { invoke } from "@tauri-apps/api/core";
    import { listen, type UnlistenFn } from "@tauri-apps/api/event";
    import { onDestroy, onMount } from "svelte";
    import { db } from "../../data/db";
    import Icon from "../ui/Icon.svelte";

    interface MtpDevice {
        vendorId: number;
        productId: number;
        manufacturer: string;
        product: string;
        serialNumber: string;
    }

    interface MtpTrack {
        handle: number;
        title: string;
        artist: string;
        album: string;
        genre: string;
        trackNumber: number;
        durationMs: number;
        playCount: number;
        filename: string;
        filesize: number;
    }

    interface TransferProgress {
        bytesSent: number;
        bytesTotal: number;
        percent: number;
        filePath: string;
    }

    // State
    let devices: MtpDevice[] = [];
    let selectedDevice: MtpDevice | null = null;
    let deviceTracks: MtpTrack[] = [];
    let detecting = false;
    let loadingTracks = false;
    let sending = false;
    let error: string | null = null;
    let statusMessage: string | null = null;
    let transferProgress: TransferProgress | null = null;

    // Songs from local library to send
    let localSongs: import("src/App").Song[] = [];
    let selectedSongIds: Set<string> = new Set();
    let sendQueue: import("src/App").Song[] = [];
    let sendIndex = 0;

    let unlistenProgress: UnlistenFn | null = null;

    onMount(async () => {
        localSongs = await db.songs
            .filter((s) => s.path.toLowerCase().endsWith(".mp3"))
            .toArray();

        unlistenProgress = await listen<TransferProgress>(
            "mtp-transfer-progress",
            (event) => {
                transferProgress = event.payload;
            }
        );
    });

    onDestroy(() => {
        unlistenProgress?.();
    });

    async function detectDevices() {
        detecting = true;
        error = null;
        devices = [];
        selectedDevice = null;
        deviceTracks = [];
        try {
            devices = await invoke<MtpDevice[]>("mtp_detect_devices");
            if (devices.length === 0) {
                statusMessage = "No MTP devices found. Is your device connected?";
            } else {
                statusMessage = `Found ${devices.length} device(s)`;
            }
        } catch (e) {
            error = `Detection failed: ${e}`;
        }
        detecting = false;
    }

    async function selectDevice(device: MtpDevice) {
        selectedDevice = device;
        await loadDeviceTracks();
    }

    async function loadDeviceTracks() {
        if (!selectedDevice) return;
        loadingTracks = true;
        error = null;
        deviceTracks = [];
        try {
            deviceTracks = await invoke<MtpTrack[]>("mtp_get_tracks", {
                serialNumber: selectedDevice.serialNumber,
            });
            statusMessage = `${deviceTracks.length} tracks on device`;
        } catch (e) {
            error = `Failed to read tracks: ${e}`;
        }
        loadingTracks = false;
    }

    function toggleSongSelection(songId: string) {
        if (selectedSongIds.has(songId)) {
            selectedSongIds.delete(songId);
        } else {
            selectedSongIds.add(songId);
        }
        selectedSongIds = selectedSongIds;
    }

    function selectAll() {
        if (selectedSongIds.size === localSongs.length) {
            selectedSongIds = new Set();
        } else {
            selectedSongIds = new Set(localSongs.map((s) => s.id));
        }
    }

    async function sendSelectedToDevice() {
        if (!selectedDevice || selectedSongIds.size === 0) return;
        sending = true;
        error = null;

        sendQueue = localSongs.filter((s) => selectedSongIds.has(s.id));
        sendIndex = 0;

        for (const song of sendQueue) {
            sendIndex++;
            statusMessage = `Sending ${sendIndex}/${sendQueue.length}: ${song.artist} - ${song.title}`;
            transferProgress = null;

            try {
                await invoke("mtp_send_track", {
                    event: {
                        filePath: song.path,
                        title: song.title || "Unknown",
                        artist: song.artist || "Unknown",
                        album: song.album || "Unknown",
                        genre: song.genre?.[0] || "",
                        trackNumber: song.trackNumber || 0,
                        durationMs: Math.round(
                            parseFloat(song.duration || "0") * 1000
                        ),
                        serialNumber: selectedDevice.serialNumber,
                    },
                });
            } catch (e) {
                error = `Failed to send "${song.title}": ${e}`;
                break;
            }
        }

        if (!error) {
            statusMessage = `Sent ${sendQueue.length} tracks successfully`;
            selectedSongIds = new Set();
            await loadDeviceTracks();
        }

        transferProgress = null;
        sending = false;
    }

    function formatDuration(ms: number): string {
        const s = Math.floor(ms / 1000);
        const m = Math.floor(s / 60);
        const sec = s % 60;
        return `${m}:${sec.toString().padStart(2, "0")}`;
    }

    function formatSize(bytes: number): string {
        if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(0)} KB`;
        return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
    }

    $: tracksWithPlays = deviceTracks.filter((t) => t.playCount > 0);
    $: totalPlays = deviceTracks.reduce((sum, t) => sum + t.playCount, 0);
</script>

<div class="zune-sync-view">
    <header>
        <h2>
            <Icon icon="mdi:usb" size={20} />
            MTP Sync
        </h2>
        <p class="subtitle">Sync music to MTP devices</p>
    </header>

    <!-- Device Detection -->
    <section class="panel">
        <div class="panel-header">
            <h3>Device</h3>
            <button
                class="action-btn"
                on:click={detectDevices}
                disabled={detecting || sending}
            >
                {#if detecting}
                    Scanning...
                {:else}
                    Detect Devices
                {/if}
            </button>
        </div>

        {#if devices.length > 0}
            <div class="device-list">
                {#each devices as device}
                    <button
                        class="device-card"
                        class:selected={selectedDevice?.serialNumber === device.serialNumber}
                        on:click={() => selectDevice(device)}
                    >
                        <div class="device-name">
                            {device.product || device.manufacturer || "MTP Device"}
                        </div>
                        <div class="device-details">
                            {device.manufacturer} — {device.product}
                            {#if device.serialNumber}
                                <span class="serial">SN: {device.serialNumber}</span>
                            {/if}
                        </div>
                    </button>
                {/each}
            </div>
        {/if}
    </section>

    {#if selectedDevice}
        <!-- Device Tracks (with play counts) -->
        <section class="panel">
            <div class="panel-header">
                <h3>
                    On Device
                    {#if deviceTracks.length > 0}
                        <span class="badge">{deviceTracks.length}</span>
                    {/if}
                </h3>
                <button
                    class="action-btn secondary"
                    on:click={loadDeviceTracks}
                    disabled={loadingTracks || sending}
                >
                    Refresh
                </button>
            </div>

            {#if loadingTracks}
                <p class="loading">Reading device library...</p>
            {:else if deviceTracks.length > 0}
                {#if totalPlays > 0}
                    <div class="play-stats">
                        <Icon icon="mdi:play-circle" size={16} />
                        <strong>{totalPlays}</strong> total plays across
                        <strong>{tracksWithPlays.length}</strong> tracks
                    </div>
                {/if}

                <div class="track-list">
                    <table>
                        <thead>
                            <tr>
                                <th class="col-title">Title</th>
                                <th class="col-artist">Artist</th>
                                <th class="col-album">Album</th>
                                <th class="col-duration">Duration</th>
                                <th class="col-plays">Plays</th>
                                <th class="col-size">Size</th>
                            </tr>
                        </thead>
                        <tbody>
                            {#each deviceTracks as track}
                                <tr class:has-plays={track.playCount > 0}>
                                    <td class="col-title">{track.title}</td>
                                    <td class="col-artist">{track.artist}</td>
                                    <td class="col-album">{track.album}</td>
                                    <td class="col-duration">{formatDuration(track.durationMs)}</td>
                                    <td class="col-plays">
                                        {#if track.playCount > 0}
                                            <span class="play-count">{track.playCount}</span>
                                        {:else}
                                            —
                                        {/if}
                                    </td>
                                    <td class="col-size">{formatSize(track.filesize)}</td>
                                </tr>
                            {/each}
                        </tbody>
                    </table>
                </div>
            {:else}
                <p class="empty">No tracks on device</p>
            {/if}
        </section>

        <!-- Send Tracks -->
        <section class="panel">
            <div class="panel-header">
                <h3>
                    Send to Device
                    {#if selectedSongIds.size > 0}
                        <span class="badge">{selectedSongIds.size}</span>
                    {/if}
                </h3>
                <div class="header-actions">
                    <button
                        class="action-btn secondary"
                        on:click={selectAll}
                        disabled={sending}
                    >
                        {selectedSongIds.size === localSongs.length
                            ? "Deselect All"
                            : "Select All"}
                    </button>
                    <button
                        class="action-btn"
                        on:click={sendSelectedToDevice}
                        disabled={sending || selectedSongIds.size === 0}
                    >
                        {#if sending}
                            Sending...
                        {:else}
                            Send {selectedSongIds.size} Track{selectedSongIds.size !== 1 ? "s" : ""}
                        {/if}
                    </button>
                </div>
            </div>

            {#if sending && transferProgress}
                <div class="progress-bar-container">
                    <div class="progress-info">
                        {statusMessage}
                    </div>
                    <div class="progress-bar">
                        <div
                            class="progress-fill"
                            style="width: {transferProgress.percent}%"
                        />
                    </div>
                    <div class="progress-detail">
                        {formatSize(transferProgress.bytesSent)} / {formatSize(transferProgress.bytesTotal)}
                        ({transferProgress.percent.toFixed(1)}%)
                    </div>
                </div>
            {/if}

            <div class="local-songs-list">
                {#if localSongs.length === 0}
                    <p class="empty">No MP3 files in library</p>
                {:else}
                    <table>
                        <thead>
                            <tr>
                                <th class="col-check" />
                                <th class="col-title">Title</th>
                                <th class="col-artist">Artist</th>
                                <th class="col-album">Album</th>
                            </tr>
                        </thead>
                        <tbody>
                            {#each localSongs as song}
                                <tr
                                    class:selected={selectedSongIds.has(song.id)}
                                    on:click={() => toggleSongSelection(song.id)}
                                >
                                    <td class="col-check">
                                        <input
                                            type="checkbox"
                                            checked={selectedSongIds.has(song.id)}
                                            on:click|stopPropagation={() => toggleSongSelection(song.id)}
                                        />
                                    </td>
                                    <td class="col-title">{song.title}</td>
                                    <td class="col-artist">{song.artist}</td>
                                    <td class="col-album">{song.album}</td>
                                </tr>
                            {/each}
                        </tbody>
                    </table>
                {/if}
            </div>
        </section>
    {/if}

    <!-- Status / Error -->
    {#if error}
        <div class="message error">
            <Icon icon="mdi:alert-circle" size={16} />
            {error}
        </div>
    {/if}
    {#if statusMessage && !error}
        <div class="message info">
            {statusMessage}
        </div>
    {/if}
</div>

<style lang="scss">
    .zune-sync-view {
        padding: 24px;
        max-width: 1000px;
        overflow-y: auto;
        height: 100%;
        color: var(--text);

        header {
            margin-bottom: 24px;

            h2 {
                display: flex;
                align-items: center;
                gap: 8px;
                margin: 0;
                font-size: 1.4em;
            }

            .subtitle {
                margin: 4px 0 0;
                opacity: 0.5;
                font-size: 0.85em;
            }
        }
    }

    .panel {
        background: var(--panel-background, rgba(255, 255, 255, 0.03));
        border: 1px solid var(--border, rgba(255, 255, 255, 0.08));
        border-radius: 8px;
        padding: 16px;
        margin-bottom: 16px;
    }

    .panel-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 12px;

        h3 {
            margin: 0;
            font-size: 1.05em;
            display: flex;
            align-items: center;
            gap: 8px;
        }

        .header-actions {
            display: flex;
            gap: 8px;
        }
    }

    .badge {
        background: var(--accent, #4a9eff);
        color: #fff;
        border-radius: 10px;
        padding: 1px 8px;
        font-size: 0.8em;
        font-weight: 600;
    }

    .action-btn {
        padding: 6px 14px;
        border-radius: 6px;
        border: 1px solid var(--accent, #4a9eff);
        background: var(--accent, #4a9eff);
        color: #fff;
        cursor: pointer;
        font-size: 0.85em;
        font-weight: 500;

        &:hover:not(:disabled) {
            filter: brightness(1.1);
        }

        &:disabled {
            opacity: 0.4;
            cursor: not-allowed;
        }

        &.secondary {
            background: transparent;
            color: var(--text);
            border-color: var(--border, rgba(255, 255, 255, 0.15));

            &:hover:not(:disabled) {
                background: rgba(255, 255, 255, 0.05);
            }
        }
    }

    .device-list {
        display: flex;
        flex-direction: column;
        gap: 8px;
    }

    .device-card {
        text-align: left;
        padding: 12px;
        border: 1px solid var(--border, rgba(255, 255, 255, 0.08));
        border-radius: 6px;
        background: transparent;
        color: var(--text);
        cursor: pointer;

        &:hover {
            background: rgba(255, 255, 255, 0.03);
        }

        &.selected {
            border-color: var(--accent, #4a9eff);
            background: rgba(74, 158, 255, 0.08);
        }

        .device-name {
            font-weight: 600;
            margin-bottom: 4px;
        }

        .device-details {
            font-size: 0.8em;
            opacity: 0.6;

            .serial {
                margin-left: 8px;
                font-family: monospace;
            }
        }
    }

    .play-stats {
        display: flex;
        align-items: center;
        gap: 6px;
        padding: 8px 12px;
        background: rgba(74, 158, 255, 0.08);
        border-radius: 6px;
        margin-bottom: 12px;
        font-size: 0.9em;
    }

    .track-list,
    .local-songs-list {
        max-height: 300px;
        overflow-y: auto;

        table {
            width: 100%;
            border-collapse: collapse;
            font-size: 0.85em;
        }

        thead {
            position: sticky;
            top: 0;
            background: var(--panel-background, rgba(30, 30, 30, 1));
        }

        th {
            text-align: left;
            padding: 6px 8px;
            font-weight: 600;
            opacity: 0.5;
            font-size: 0.85em;
            text-transform: uppercase;
            border-bottom: 1px solid var(--border, rgba(255, 255, 255, 0.08));
        }

        td {
            padding: 6px 8px;
            border-bottom: 1px solid var(--border, rgba(255, 255, 255, 0.04));
        }

        tbody tr {
            &:hover {
                background: rgba(255, 255, 255, 0.03);
            }

            &.selected {
                background: rgba(74, 158, 255, 0.1);
            }

            &.has-plays {
                .col-plays {
                    color: var(--accent, #4a9eff);
                    font-weight: 600;
                }
            }
        }
    }

    .local-songs-list {
        tbody tr {
            cursor: pointer;
        }
    }

    .col-check {
        width: 30px;
    }

    .col-duration,
    .col-plays,
    .col-size {
        text-align: right;
        white-space: nowrap;
    }

    .play-count {
        background: var(--accent, #4a9eff);
        color: #fff;
        border-radius: 8px;
        padding: 1px 6px;
        font-size: 0.85em;
    }

    .progress-bar-container {
        margin-bottom: 12px;
        padding: 12px;
        background: rgba(255, 255, 255, 0.02);
        border-radius: 6px;
    }

    .progress-info {
        font-size: 0.85em;
        margin-bottom: 6px;
    }

    .progress-bar {
        height: 6px;
        background: rgba(255, 255, 255, 0.1);
        border-radius: 3px;
        overflow: hidden;
    }

    .progress-fill {
        height: 100%;
        background: var(--accent, #4a9eff);
        border-radius: 3px;
        transition: width 0.2s ease;
    }

    .progress-detail {
        font-size: 0.8em;
        opacity: 0.5;
        margin-top: 4px;
    }

    .message {
        display: flex;
        align-items: center;
        gap: 8px;
        padding: 10px 14px;
        border-radius: 6px;
        font-size: 0.9em;
        margin-top: 8px;

        &.error {
            background: rgba(255, 80, 80, 0.1);
            border: 1px solid rgba(255, 80, 80, 0.2);
            color: #ff6b6b;
        }

        &.info {
            background: rgba(255, 255, 255, 0.03);
            opacity: 0.6;
        }
    }

    .loading,
    .empty {
        opacity: 0.4;
        font-style: italic;
        padding: 8px 0;
    }
</style>
