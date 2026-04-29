//! BLE GATT peripheral transport.
//!
//! Full implementation is compiled on Linux (BlueZ) with `--features ble`
//! only. All other configurations expose a stub that returns a clear runtime
//! error so the rest of the codebase always compiles cleanly.
//!
//! # Protocol  (mirrors internal/transport/ble/ble.go)
//!
//! Nordic UART-derived service (`6e40000x-b5a3-f393-e0a9-e50e24dcca9e`):
//!
//! | Char  | UUID …0002 | UUID …0003 | UUID …0004 |
//! |-------|------------|------------|------------|
//! | Role  | Request    | Response   | Status     |
//! | Props | Write/WWR  | Notify     | Notify     |
//!
//! Framing: `[u16-BE length][payload]`; a `length=0` fragment = end-of-message.
//! Fragment size: ≤ 180 bytes.
//!
//! # Two-phase relay dance
//!
//! **Phase 1** – Central writes empty EOM trigger → peripheral replies with
//!   its signed `EnrollRequest` JSON envelope.
//!
//! **Phase 2** – Central writes the server's `EnrollResponse` JSON (chunked)
//!   → peripheral verifies and applies the provisioning bundle, then exits.

/// Run as a BLE GATT peripheral and complete one enrollment cycle.
///
/// On Linux with `--features ble` this is a full BlueZ-backed implementation.
/// On any other platform/feature combination it returns an error immediately.
///
/// `cancel` may be polled by the implementation to abort an in-flight session
/// when another transport (e.g. an HTTP rescanner) wins the race. When it is
/// observed `true` the call returns `Err(BleCancelledError)` promptly.
// Suppress the unreachable-code lint for the fallback Err() on ble+linux builds.
#[cfg_attr(all(feature = "ble", target_os = "linux"), allow(unreachable_code))]
pub fn run_ble(
    cfg: &crate::enroll::Config,
    cancel: std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> crate::Result<()> {
    #[cfg(all(feature = "ble", target_os = "linux"))]
    return imp::run(cfg, cancel);

    let _ = cfg;
    let _ = cancel;
    Err("BLE peripheral transport requires Linux with BlueZ; \
         rebuild with `--features ble` targeting a Linux host. \
         Alternatively use the Go agent (bin/ztp-agent-ble) for BLE support."
        .into())
}

/// Sentinel error returned when `run_ble` is aborted via the cancel flag.
/// Treated as a non-terminal "lost the race" error by `run_multi_transport`.
#[derive(Debug)]
pub struct BleCancelledError;

impl std::fmt::Display for BleCancelledError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "BLE peripheral cancelled")
    }
}

impl std::error::Error for BleCancelledError {}

// ── Linux + ble feature ───────────────────────────────────────────────────

#[cfg(all(feature = "ble", target_os = "linux"))]
mod imp {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use bluer::{
        adv::{Advertisement, Type as AdvType},
        gatt::{
            local::{
                characteristic_control, Application, Characteristic, CharacteristicControlEvent,
                CharacteristicNotify, CharacteristicNotifyMethod, CharacteristicWrite,
                CharacteristicWriteMethod, Service,
            },
            CharacteristicWriter,
        },
        Uuid,
    };
    use futures::StreamExt;
    use std::collections::BTreeSet;
    use tokio::io::AsyncWriteExt;

    // ---- UUIDs (Nordic UART Service-derived) --------------------------------
    const SVC_UUID:       &str = "6e400001-b5a3-f393-e0a9-e50e24dcca9e";
    const REQ_UUID:       &str = "6e400002-b5a3-f393-e0a9-e50e24dcca9e";
    const RESP_UUID:      &str = "6e400003-b5a3-f393-e0a9-e50e24dcca9e";
    const STAT_UUID:      &str = "6e400004-b5a3-f393-e0a9-e50e24dcca9e";
    /// Write an RFC3339 UTC timestamp here before enrollment to correct the
    /// device's clock offset (Option 3 — BLE time sync).
    const TIME_SYNC_UUID: &str = "6e400005-b5a3-f393-e0a9-e50e24dcca9e";

    // ---- Protocol constants -------------------------------------------------
    const FRAG_SIZE: usize = 180;

    const STATUS_RELAYING: u8 = 1;
    const STATUS_DONE:     u8 = 2;
    const STATUS_ERROR:    u8 = 3;

    fn uuid(s: &str) -> Uuid {
        s.parse().expect("hardcoded UUID is valid")
    }

    // ── Entry point ──────────────────────────────────────────────────────────

    pub fn run(
        cfg: &crate::enroll::Config,
        cancel: std::sync::Arc<std::sync::atomic::AtomicBool>,
    ) -> crate::Result<()> {
        let device_id = crate::enroll::resolve_device_id(&cfg.device_id)?;
        log::info!("enrolling device device_id={device_id}");

        let server_pub: Option<ed25519_dalek::VerifyingKey> = cfg.server_pub_key
            .as_ref()
            .map(|k| crate::sign::decode_public_key(&STANDARD.encode(k)))
            .transpose()?;

        // clock_offset_ns stores the running clock correction from either
        // the TimeSyncUUID write (Option 3) or a server rejection
        // (Option 1). Stored as nanoseconds in an AtomicI64 so the async
        // write event callback can update it safely.
        let clock_offset_ns = std::sync::Arc::new(std::sync::atomic::AtomicI64::new(0));

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|e| format!("tokio runtime: {e}"))?;

        rt.block_on(serve(cfg, device_id, server_pub, clock_offset_ns, cancel))
    }

    /// Build a fresh enroll envelope + ephemeral X25519 key pair.
    fn make_envelope(
        cfg: &crate::enroll::Config,
        device_id: &str,
        clock_offset: chrono::Duration,
    ) -> crate::Result<(Vec<u8>, [u8; 32])> {
        let mut cfg_with_offset = cfg.clone();
        cfg_with_offset.clock_offset = clock_offset;
        let (eph_priv, eph_pub) = crate::encrypt::generate_x25519()?;
        let req = crate::enroll::build_request(device_id, &cfg_with_offset, &STANDARD.encode(eph_pub));
        let env = crate::sign::sign(&req, cfg.identity.signing_key(), "device")?;
        let env_json = serde_json::to_vec(&env)
            .map_err(|e| format!("marshal enroll envelope: {e}"))?;
        Ok((env_json, eph_priv))
    }

    /// Return a name suitable for the BLE advertising payload.
    // Use a fixed short name to ensure it is compatible across
    // different OS's
    fn ble_advertised_name(id: &str, prefix: &str) -> String {
        format!("ztp")
    }

    // ── Async serve loop ─────────────────────────────────────────────────────

    async fn serve(
        cfg: &crate::enroll::Config,
        device_id: String,
        server_pub: Option<ed25519_dalek::VerifyingKey>,
        clock_offset_ns: std::sync::Arc<std::sync::atomic::AtomicI64>,
        cancel: std::sync::Arc<std::sync::atomic::AtomicBool>,
    ) -> crate::Result<()> {
        // ---- BlueZ session + adapter ----------------------------------------
        let session = bluer::Session::new()
            .await
            .map_err(|e| format!("BLE session: {e}"))?;
        let adapter = session
            .default_adapter()
            .await
            .map_err(|e| format!("BLE adapter: {e}"))?;
        adapter
            .set_powered(true)
            .await
            .map_err(|e| format!("power BLE adapter: {e}"))?;

        // ---- Channel for incoming write fragments ----------------------------
        // The Go relay calls WriteWithoutResponse for each framed fragment.
        // BlueZ routes these as individual WriteValue D-Bus calls, which bluer
        // delivers via CharacteristicWriteMethod::Fun — NOT via the Io/socket
        // path (AcquireWrite).  We forward each call through an MPSC channel
        // into the main select! loop.
        let (write_tx, mut write_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();

        // ---- Channel for TimeSyncUUID writes (Option 3) ---------------------
        // The relay writes an RFC3339 timestamp here before phase 1 so the
        // device can correct its clock before building the enrollment envelope.
        let (time_sync_tx, mut time_sync_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();

        // ---- Control handles for the two notify characteristics -------------
        let (mut resp_ctrl, resp_handle) = characteristic_control();
        let (mut stat_ctrl, stat_handle) = characteristic_control();

        let svc_uuid = uuid(SVC_UUID);
        let app = Application {
            services: vec![Service {
                uuid: svc_uuid,
                primary: true,
                characteristics: vec![
                    // Request: central writes fragments here (WriteWithoutResponse)
                    Characteristic {
                        uuid: uuid(REQ_UUID),
                        write: Some(CharacteristicWrite {
                            write: true,
                            write_without_response: true,
                            method: CharacteristicWriteMethod::Fun(Box::new(
                                move |value, _req| {
                                    let tx = write_tx.clone();
                                    Box::pin(async move {
                                        tx.send(value).ok();
                                        Ok(())
                                    })
                                },
                            )),
                            ..Default::default()
                        }),
                        ..Default::default()
                    },
                    // Response: peripheral notifies response fragments here
                    Characteristic {
                        uuid: uuid(RESP_UUID),
                        notify: Some(CharacteristicNotify {
                            notify: true,
                            method: CharacteristicNotifyMethod::Io,
                            ..Default::default()
                        }),
                        control_handle: resp_handle,
                        ..Default::default()
                    },
                    // Status: peripheral notifies status byte here
                    Characteristic {
                        uuid: uuid(STAT_UUID),
                        notify: Some(CharacteristicNotify {
                            notify: true,
                            method: CharacteristicNotifyMethod::Io,
                            ..Default::default()
                        }),
                        control_handle: stat_handle,
                        ..Default::default()
                    },
                    // TimeSyncUUID: relay writes RFC3339 timestamp to sync device clock
                    Characteristic {
                        uuid: uuid(TIME_SYNC_UUID),
                        write: Some(CharacteristicWrite {
                            write: true,
                            write_without_response: true,
                            method: CharacteristicWriteMethod::Fun(Box::new(
                                move |value, _req| {
                                    let tx = time_sync_tx.clone();
                                    Box::pin(async move {
                                        tx.send(value).ok();
                                        Ok(())
                                    })
                                },
                            )),
                            ..Default::default()
                        }),
                        ..Default::default()
                    },
                ],
                ..Default::default()
            }],
            ..Default::default()
        };

        let _app_handle = adapter
            .serve_gatt_application(app)
            .await
            .map_err(|e| format!("register GATT application: {e}"))?;

        // ---- Advertising ----------------------------------------------------
        // Prefix the device id so ZTP peripherals are recognisable in BLE
        // scanners. BlueZ overflows long names into the scan-response PDU.
        let adv_name = ble_advertised_name(&device_id, &cfg.ble_name_prefix);
        log::info!("BLE: advertising peripheral name={adv_name}, device_id={device_id}");
        let mut svc_uuids = BTreeSet::new();
        svc_uuids.insert(svc_uuid);
        let adv = Advertisement {
            advertisement_type: AdvType::Peripheral,
            service_uuids: svc_uuids,
            local_name: Some(adv_name),
            ..Default::default()
        };
        let _adv_handle = adapter
            .advertise(adv)
            .await
            .map_err(|e| format!("BLE advertise: {e}"))?;

        log::info!("BLE peripheral advertising (adapter={}), waiting for relay", adapter.name());

        // ---- Initial enrollment envelope ------------------------------------
        // Built here so the timestamp is fresh; regenerated on rejection/retry.
        // clock_offset is zero at first start; updated by TimeSyncUUID writes
        // (Option 3) or server rejection responses (Option 1).
        let current_offset = || chrono::Duration::nanoseconds(
            clock_offset_ns.load(std::sync::atomic::Ordering::Relaxed)
        );
        let (mut env_json, mut eph_priv) = make_envelope(cfg, &device_id, current_offset())?;;

        // ---- Event loop -----------------------------------------------------
        // resp_writer / stat_writer are CharacteristicWriter (implements AsyncWrite).
        // We receive them when the central subscribes to notifications (Notify event).
        let mut req_buf: Vec<u8> = Vec::new();
        let mut resp_writer: Option<CharacteristicWriter> = None;
        let mut stat_writer: Option<CharacteristicWriter> = None;
        let mut phase: u32 = 0;

        loop {
            tokio::select! {
                // ---- Cancellation poll (HTTP rescanner won the race) --------
                // We don't have an OS signal here, so poll the AtomicBool every
                // 250 ms. Latency on cancel is therefore ≤ 250 ms, which is
                // imperceptible compared to BLE relay round-trips.
                _ = tokio::time::sleep(std::time::Duration::from_millis(250)) => {
                    if cancel.load(std::sync::atomic::Ordering::Relaxed) {
                        log::info!("BLE: cancel signal received, stopping peripheral");
                        return Err(Box::new(super::BleCancelledError));
                    }
                }

                // ---- TimeSyncUUID write (Option 3: relay sets device clock) --
                ts_bytes = time_sync_rx.recv() => {
                    let Some(ts_bytes) = ts_bytes else { break };
                    if let Ok(s) = std::str::from_utf8(&ts_bytes) {
                        if let Ok(server_time) = chrono::DateTime::parse_from_rfc3339(s.trim()) {
                            let server_time: chrono::DateTime<chrono::Utc> = server_time.into();
                            let offset_ns = server_time
                                .signed_duration_since(chrono::Utc::now())
                                .num_nanoseconds()
                                .unwrap_or(0);
                            clock_offset_ns.store(offset_ns, std::sync::atomic::Ordering::Relaxed);
                            log::info!("BLE: time sync from relay server_time={server_time} offset_ns={offset_ns}");
                        }
                    }
                }

                fragment = write_rx.recv() => {
                    let Some(fragment) = fragment else { break };
                    if fragment.len() < 2 {
                        continue; // malformed — skip
                    }
                    let n = u16::from_be_bytes([fragment[0], fragment[1]]) as usize;

                    if n == 0 {
                        // End-of-message: process accumulated request.
                        let req = std::mem::take(&mut req_buf);
                        phase += 1;
                        match phase {
                            1 => {
                                // Phase 1: relay triggered — build a fresh
                                // envelope with the current clock offset.
                                log::info!("BLE phase 1: sending enroll envelope to relay");
                                match make_envelope(cfg, &device_id, current_offset()) {
                                    Ok((new_json, new_priv)) => {
                                        env_json = new_json;
                                        eph_priv = new_priv;
                                    }
                                    Err(e) => {
                                        log::error!("BLE phase 1: build envelope: {e}");
                                        return Err(e);
                                    }
                                }
                                match (resp_writer.as_mut(), stat_writer.as_mut()) {
                                    (Some(rw), Some(sw)) => {
                                        notify_response(rw, sw, &env_json).await?;
                                    }
                                    _ => {
                                        log::warn!(
                                            "BLE phase 1: central has not subscribed to \
                                             notifications yet; cannot send envelope"
                                        );
                                    }
                                }
                            }
                            2 => {
                                log::info!("BLE phase 2: received server response, applying bundle");
                                // Deserialise first so we can detect rejection and retry
                                // without dying, rather than returning a hard error.
                                let resp_result: Result<crate::wire::EnrollResponse, _> =
                                    serde_json::from_slice(&req);
                                match resp_result {
                                    Err(e) => {
                                        log::error!("BLE phase 2: decode server response: {e}");
                                        if let Some(sw) = stat_writer.as_mut() {
                                            sw.write_all(&[STATUS_ERROR]).await.ok();
                                        }
                                        return Err(format!("decode server response JSON: {e}").into());
                                    }
                                    Ok(ref resp)
                                        if matches!(
                                            resp.status,
                                            crate::wire::EnrollStatus::Rejected
                                                | crate::wire::EnrollStatus::Pending
                                        ) =>
                                    {
                                        // Option 1: extract server_time to auto-correct clock.
                                        if let Some(server_time) = resp.server_time {
                                            let offset_ns = server_time
                                                .signed_duration_since(chrono::Utc::now())
                                                .num_nanoseconds()
                                                .unwrap_or(0);
                                            clock_offset_ns.store(
                                                offset_ns,
                                                std::sync::atomic::Ordering::Relaxed,
                                            );
                                            log::info!(
                                                "BLE: auto-correcting clock from server \
                                                 response offset_ns={offset_ns}"
                                            );
                                        }
                                        let reason = resp.reason.clone().unwrap_or_default();
                                        log::warn!(
                                            "BLE phase 2: server {:?}: {reason}; \
                                             regenerating enrollment envelope and \
                                             waiting for next relay connection",
                                            resp.status,
                                        );
                                        if let Some(sw) = stat_writer.as_mut() {
                                            sw.write_all(&[STATUS_ERROR]).await.ok();
                                        }
                                        match make_envelope(cfg, &device_id, current_offset()) {
                                            Ok((new_json, new_priv)) => {
                                                env_json = new_json;
                                                eph_priv = new_priv;
                                                phase = 0;
                                                log::info!("BLE: fresh envelope ready, advertising for retry");
                                            }
                                            Err(e) => {
                                                log::error!("BLE: failed to regenerate envelope: {e}");
                                                return Err(e);
                                            }
                                        }
                                        // continue the select! loop
                                    }
                                    Ok(resp) => {
                                        match crate::enroll::handle_accepted(
                                            resp,
                                            &eph_priv,
                                            server_pub.as_ref(),
                                            cfg,
                                            "",
                                        ) {
                                            Ok(()) => {
                                                if let Some(sw) = stat_writer.as_mut() {
                                                    sw.write_all(&[STATUS_DONE]).await.ok();
                                                }
                                                return Ok(()); // enrollment complete
                                            }
                                            Err(e) => {
                                                log::error!("BLE phase 2: bundle apply failed: {e}");
                                                if let Some(sw) = stat_writer.as_mut() {
                                                    sw.write_all(&[STATUS_ERROR]).await.ok();
                                                }
                                                return Err(e);
                                            }
                                        }
                                    }
                                }
                            }
                            _ => {
                                log::warn!("BLE: unexpected request cycle (phase={phase}), ignoring");
                            }
                        }
                    } else if 2 + n <= fragment.len() {
                        req_buf.extend_from_slice(&fragment[2..2 + n]);
                    }
                }

                event = resp_ctrl.next() => {
                    let Some(event) = event else { break };
                    if let CharacteristicControlEvent::Notify(writer) = event {
                        log::debug!("BLE: central subscribed to response characteristic");
                        resp_writer = Some(writer);
                    }
                }

                event = stat_ctrl.next() => {
                    let Some(event) = event else { break };
                    if let CharacteristicControlEvent::Notify(writer) = event {
                        log::debug!("BLE: central subscribed to status characteristic");
                        stat_writer = Some(writer);
                    }
                }
            }
        }

        Err("BLE serve loop ended unexpectedly before enrollment completed".into())
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    /// Send `data` back to the relay as length-prefixed fragments.
    ///
    /// `CharacteristicWriter` implements `AsyncWrite`; each `write_all` call
    /// causes BlueZ to deliver one GATT notification to the central.
    async fn notify_response(
        resp: &mut CharacteristicWriter,
        stat: &mut CharacteristicWriter,
        data: &[u8],
    ) -> crate::Result<()> {
        stat.write_all(&[STATUS_RELAYING])
            .await
            .map_err(|e| format!("notify STATUS_RELAYING: {e}"))?;

        for chunk in data.chunks(FRAG_SIZE) {
            let mut frag = Vec::with_capacity(2 + chunk.len());
            frag.extend_from_slice(&(chunk.len() as u16).to_be_bytes());
            frag.extend_from_slice(chunk);
            resp.write_all(&frag)
                .await
                .map_err(|e| format!("notify response fragment: {e}"))?;
        }
        // End-of-message sentinel.
        resp.write_all(&[0u8, 0u8])
            .await
            .map_err(|e| format!("notify EOM: {e}"))?;
        stat.write_all(&[STATUS_DONE])
            .await
            .map_err(|e| format!("notify STATUS_DONE: {e}"))?;

        Ok(())
    }

}

