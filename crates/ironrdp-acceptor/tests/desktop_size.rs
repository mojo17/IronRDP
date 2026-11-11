#![allow(
    unused_crate_dependencies,
    reason = "the crate's own dependencies are linked into its tests"
)]
#![allow(clippy::panic, reason = "panic is acceptable in tests")]
#![allow(clippy::unwrap_used, reason = "unwrap is fine in tests")]
//! Desktop size negotiation in the acceptor: the size policy hook, the
//! honor-client-size flag, and the default (neither) which must not change
//! anything on the wire.
//!
//! The acceptor is driven sans-IO against a real `ClientConnector`, so every
//! PDU the acceptor decodes is one a real client encoder produced.

use core::net::{Ipv4Addr, SocketAddr};
use core::sync::atomic::{AtomicUsize, Ordering};
use std::collections::VecDeque;
use std::sync::Arc;

use ironrdp_acceptor::{Acceptor, AcceptorResult};
use ironrdp_connector::{ClientConnector, Credentials, DesktopSize, Sequence as _, State as _};
use ironrdp_core::{WriteBuf, decode, encode_vec};
use ironrdp_pdu::gcc::{self, ClientEarlyCapabilityFlags};
use ironrdp_pdu::mcs::{self, McsMessage};
use ironrdp_pdu::nego::SecurityProtocol;
use ironrdp_pdu::rdp::capability_sets::{self, CapabilitySet, MajorPlatformType};
use ironrdp_pdu::rdp::headers::{ShareControlHeader, ShareControlPdu, ShareDataPdu};
use ironrdp_pdu::x224::{X224, X224Data};

const SERVER_SIZE: DesktopSize = DesktopSize {
    width: 1920,
    height: 1080,
};

fn size(width: u16, height: u16) -> DesktopSize {
    DesktopSize { width, height }
}

fn client_config(desktop_size: DesktopSize) -> ironrdp_connector::Config {
    ironrdp_connector::Config {
        desktop_size,
        desktop_scale_factor: 0,
        enable_tls: true,
        enable_credssp: false,
        credentials: Credentials::UsernamePassword {
            username: "test".into(),
            password: "test".into(),
        },
        domain: None,
        client_build: 0,
        client_name: "test".into(),
        keyboard_type: gcc::KeyboardType::IbmEnhanced,
        keyboard_subtype: 0,
        keyboard_layout: 0,
        keyboard_functional_keys_count: 12,
        ime_file_name: String::new(),
        bitmap: None,
        dig_product_id: String::new(),
        client_dir: String::new(),
        platform: MajorPlatformType::UNIX,
        hardware_id: None,
        request_data: None,
        autologon: false,
        enable_audio_playback: false,
        license_cache: None,
        compression_type: None,
        enable_server_pointer: false,
        pointer_software_rendering: false,
        multitransport_flags: None,
        performance_flags: Default::default(),
        timezone_info: Default::default(),
        alternate_shell: String::new(),
        work_dir: String::new(),
    }
}

fn server_capabilities(desktop_size: DesktopSize) -> Vec<CapabilitySet> {
    vec![
        CapabilitySet::General(capability_sets::General {
            extra_flags: capability_sets::GeneralExtraFlags::FASTPATH_OUTPUT_SUPPORTED,
            ..Default::default()
        }),
        CapabilitySet::Bitmap(capability_sets::Bitmap {
            pref_bits_per_pix: 32,
            desktop_width: desktop_size.width,
            desktop_height: desktop_size.height,
            desktop_resize_flag: true,
            drawing_flags: capability_sets::BitmapDrawingFlags::empty(),
        }),
    ]
}

fn new_acceptor() -> Acceptor {
    Acceptor::new(
        SecurityProtocol::SSL,
        SERVER_SIZE,
        server_capabilities(SERVER_SIZE),
        None,
    )
}

/// Rewrites the client's MCS Connect Initial so that its core data requests
/// `requested` and (optionally) advertises Monitor Layout PDU support, which
/// the connector never does by itself. Any other PDU is returned untouched.
fn rewrite_connect_initial(pdu: &[u8], requested: DesktopSize, monitor_layout: bool) -> Option<Vec<u8>> {
    let data = decode::<X224<X224Data<'_>>>(pdu).ok()?.0;
    let connect_initial = decode::<mcs::ConnectInitial>(data.data.as_ref()).ok()?;
    let mut gcc_blocks = connect_initial.conference_create_request.into_gcc_blocks();

    gcc_blocks.core.desktop_width = requested.width;
    gcc_blocks.core.desktop_height = requested.height;
    if monitor_layout {
        let flags = gcc_blocks
            .core
            .optional_data
            .early_capability_flags
            .get_or_insert(ClientEarlyCapabilityFlags::empty());
        *flags |= ClientEarlyCapabilityFlags::SUPPORT_MONITOR_LAYOUT_PDU;
    }

    let connect_initial = mcs::ConnectInitial::with_gcc_blocks(gcc_blocks).unwrap();
    let payload = encode_vec(&connect_initial).unwrap();
    Some(encode_vec(&X224(X224Data { data: payload.into() })).unwrap())
}

fn decode_share_control(pdu: &[u8]) -> Option<ShareControlPdu> {
    let McsMessage::SendDataIndication(indication) = decode::<X224<McsMessage<'_>>>(pdu).ok()?.0 else {
        return None;
    };
    let header = decode::<ShareControlHeader>(indication.user_data.as_ref()).ok()?;
    Some(header.share_control_pdu)
}

fn is_monitor_layout(pdu: &[u8]) -> bool {
    matches!(
        decode_share_control(pdu),
        Some(ShareControlPdu::Data(data)) if matches!(data.share_data_pdu, ShareDataPdu::MonitorLayout(_))
    )
}

/// Everything observable from one handshake.
struct Handshake {
    /// Every PDU the acceptor wrote, in order.
    server_pdus: Vec<Vec<u8>>,
    result: AcceptorResult,
    requested_seen_by_acceptor: Option<DesktopSize>,
    /// The size the client ended up with (it adopts the Demand Active size).
    client_size: DesktopSize,
}

impl Handshake {
    fn share_control_pdus(&self) -> impl Iterator<Item = (&[u8], ShareControlPdu)> {
        self.server_pdus
            .iter()
            .filter_map(|pdu| Some((pdu.as_slice(), decode_share_control(pdu)?)))
    }

    /// The raw Demand Active PDU and the desktop size in its Bitmap capset.
    fn demand_active(&self) -> (&[u8], DesktopSize) {
        self.share_control_pdus()
            .find_map(|(raw, pdu)| match pdu {
                ShareControlPdu::ServerDemandActive(demand) => {
                    let bitmap = demand.pdu.capability_sets.iter().find_map(|c| match c {
                        CapabilitySet::Bitmap(b) => Some(size(b.desktop_width, b.desktop_height)),
                        _ => None,
                    });
                    Some((raw, bitmap.expect("Bitmap capset in Demand Active")))
                }
                _ => None,
            })
            .expect("a Demand Active PDU")
    }

    /// The raw Monitor Layout PDU and its monitors, if one was sent.
    fn monitor_layout(&self) -> Option<(&[u8], Vec<gcc::Monitor>)> {
        self.share_control_pdus().find_map(|(raw, pdu)| match pdu {
            ShareControlPdu::Data(data) => match data.share_data_pdu {
                ShareDataPdu::MonitorLayout(layout) => Some((raw, layout.monitors)),
                _ => None,
            },
            _ => None,
        })
    }
}

/// Runs a full connection sequence between `acceptor` and a `ClientConnector`
/// whose core data requests `requested`.
fn handshake(mut acceptor: Acceptor, requested: DesktopSize, monitor_layout: bool) -> Handshake {
    let client_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, 33890));
    let mut client = ClientConnector::new(client_config(requested), client_addr);

    let mut to_server: VecDeque<Vec<u8>> = VecDeque::new();
    let mut to_client: VecDeque<Vec<u8>> = VecDeque::new();
    let mut server_pdus = Vec::new();

    for _ in 0..200 {
        let mut progressed = false;

        if !client.state().is_terminal() {
            let input = if client.next_pdu_hint().is_none() {
                Some(Vec::new())
            } else {
                to_client.pop_front()
            };
            if let Some(input) = input {
                let mut output = WriteBuf::new();
                client.step(&input, &mut output).expect("client step");
                if !output.filled().is_empty() {
                    let pdu = output.filled().to_vec();
                    to_server.push_back(rewrite_connect_initial(&pdu, requested, monitor_layout).unwrap_or(pdu));
                }
                progressed = true;
            }
        }

        if !acceptor.state().is_terminal() {
            let input = if acceptor.next_pdu_hint().is_none() {
                Some(Vec::new())
            } else {
                to_server.pop_front()
            };
            if let Some(input) = input {
                let mut output = WriteBuf::new();
                acceptor.step(&input, &mut output).expect("acceptor step");
                if !output.filled().is_empty() {
                    let pdu = output.filled().to_vec();
                    // The connector does not implement the optional Monitor
                    // Layout PDU, so it is recorded but not delivered.
                    if !is_monitor_layout(&pdu) {
                        to_client.push_back(pdu.clone());
                    }
                    server_pdus.push(pdu);
                }
                progressed = true;
            }
        }

        if !progressed {
            break;
        }
    }

    assert!(
        acceptor.state().is_terminal(),
        "acceptor stuck in {}",
        acceptor.state().name()
    );

    let requested_seen_by_acceptor = acceptor.client_requested_desktop_size();
    let result = acceptor.get_result().expect("acceptor result");
    let client_size = match client.state {
        ironrdp_connector::ClientConnectorState::Connected { ref result } => result.desktop_size,
        ref state => panic!("client stuck in {}", state.name()),
    };

    Handshake {
        server_pdus,
        result,
        requested_seen_by_acceptor,
        client_size,
    }
}

fn exclusive_monitor(desktop_size: DesktopSize) -> gcc::Monitor {
    gcc::Monitor {
        left: 0,
        top: 0,
        right: i32::from(desktop_size.width),
        bottom: i32::from(desktop_size.height),
        flags: gcc::MonitorFlags::PRIMARY,
    }
}

/// A policy that clamps to [320, 4096] and floors to even: a stand-in for a
/// real embedder's barricade.
fn clamping_policy(requested: DesktopSize) -> DesktopSize {
    if requested.width == 0 || requested.height == 0 {
        return size(1280, 720);
    }
    size(
        requested.width.clamp(320, 4096) & !1,
        requested.height.clamp(320, 4096) & !1,
    )
}

#[test]
fn policy_decides_the_size_everywhere() {
    for (requested, served) in [
        (size(2240, 1473), size(2240, 1472)),
        (size(1281, 800), size(1280, 800)),
        (size(10000, 10000), size(4096, 4096)),
        (size(u16::MAX, u16::MAX), size(4096, 4096)),
        (size(0, 0), size(1280, 720)),
        (size(1, 1), size(320, 320)),
    ] {
        let mut acceptor = new_acceptor();
        acceptor.set_desktop_size_policy(Arc::new(clamping_policy));

        let handshake = handshake(acceptor, requested, true);

        assert_eq!(handshake.demand_active().1, served, "Demand Active for {requested:?}");
        let (_, monitors) = handshake.monitor_layout().expect("a Monitor Layout PDU");
        assert_eq!(
            monitors,
            vec![exclusive_monitor(served)],
            "Monitor Layout for {requested:?}"
        );
        assert_eq!(
            handshake.result.desktop_size, served,
            "AcceptorResult for {requested:?}"
        );
        assert_eq!(handshake.client_size, served, "client-adopted size for {requested:?}");
        assert_eq!(handshake.requested_seen_by_acceptor, Some(requested));
    }
}

#[test]
fn policy_is_called_once_with_the_raw_request() {
    let calls = Arc::new(AtomicUsize::new(0));
    let seen = Arc::new(std::sync::Mutex::new(None));

    let mut acceptor = new_acceptor();
    acceptor.set_desktop_size_policy({
        let calls = Arc::clone(&calls);
        let seen = Arc::clone(&seen);
        Arc::new(move |requested| {
            calls.fetch_add(1, Ordering::SeqCst);
            *seen.lock().unwrap() = Some(requested);
            size(800, 600)
        })
    });
    assert_eq!(acceptor.client_requested_desktop_size(), None, "nothing received yet");

    let handshake = handshake(acceptor, size(1281, 801), false);

    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(*seen.lock().unwrap(), Some(size(1281, 801)));
    assert_eq!(handshake.demand_active().1, size(800, 600));
    assert!(
        handshake.monitor_layout().is_none(),
        "client did not ask for a Monitor Layout PDU"
    );
}

#[test]
fn policy_returning_an_empty_size_keeps_the_server_size() {
    for empty in [size(0, 0), size(0, 600), size(800, 0)] {
        let mut acceptor = new_acceptor();
        acceptor.set_desktop_size_policy(Arc::new(move |_| empty));

        let handshake = handshake(acceptor, size(1024, 768), true);

        assert_eq!(handshake.demand_active().1, SERVER_SIZE);
        assert_eq!(handshake.result.desktop_size, SERVER_SIZE);
        let (_, monitors) = handshake.monitor_layout().unwrap();
        assert_eq!(monitors, vec![exclusive_monitor(SERVER_SIZE)]);
    }
}

#[test]
fn policy_takes_precedence_over_honor_flag() {
    let mut acceptor = new_acceptor();
    acceptor.set_honor_client_desktop_size(true);
    acceptor.set_desktop_size_policy(Arc::new(|_| size(800, 600)));

    // 1024×768 is in the honor flag's band, so the flag alone would adopt it.
    let handshake = handshake(acceptor, size(1024, 768), true);

    assert_eq!(handshake.demand_active().1, size(800, 600));
    assert_eq!(handshake.result.desktop_size, size(800, 600));
}

#[test]
fn honor_flag_adopts_in_range_requests_only() {
    for (requested, served) in [
        (size(1024, 768), size(1024, 768)),
        (size(1281, 801), size(1281, 801)),
        (size(199, 768), SERVER_SIZE),
        (size(1024, 8193), SERVER_SIZE),
        (size(0, 0), SERVER_SIZE),
    ] {
        let mut acceptor = new_acceptor();
        acceptor.set_honor_client_desktop_size(true);

        let handshake = handshake(acceptor, requested, true);

        assert_eq!(handshake.demand_active().1, served, "Demand Active for {requested:?}");
        assert_eq!(
            handshake.result.desktop_size, served,
            "AcceptorResult for {requested:?}"
        );
    }
}

/// Without a policy and without the honor flag, the client's requested size
/// has no effect on any byte the acceptor writes.
#[test]
fn default_ignores_the_requested_size() {
    let baseline = handshake(new_acceptor(), SERVER_SIZE, true);

    for requested in [size(2240, 1473), size(0, 0), size(u16::MAX, u16::MAX)] {
        let handshake = handshake(new_acceptor(), requested, true);

        assert_eq!(
            handshake.server_pdus, baseline.server_pdus,
            "server output for {requested:?}"
        );
        assert_eq!(handshake.result.desktop_size, SERVER_SIZE);
        assert_eq!(handshake.requested_seen_by_acceptor, Some(requested));
    }
}

/// Without a policy and without the honor flag, Demand Active and Monitor
/// Layout are byte-identical to what the acceptor produced before either
/// option existed. The expected bytes were captured from the pre-change
/// acceptor (fork rev 89f658be) with this same driver.
#[test]
fn default_encode_is_byte_identical_to_pre_policy_acceptor() {
    let handshake = handshake(new_acceptor(), size(2240, 1473), true);

    assert_eq!(hex(handshake.demand_active().0), GOLDEN_DEMAND_ACTIVE);
    assert_eq!(hex(handshake.monitor_layout().unwrap().0), GOLDEN_MONITOR_LAYOUT);
    assert_eq!(hex(&handshake.server_pdus.concat()), GOLDEN_ALL_SERVER_PDUS);
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

const GOLDEN_DEMAND_ACTIVE: &str = "0300005902f08068000103eb704b4b001100eb030000000001003800000200000001001800000000000002000000000100000000000000000002001c0020000100010001008007380400000100010000000100000000000000";
const GOLDEN_MONITOR_LAYOUT: &str =
    "0300003802f08068000103eb702a2a001700eb03000000000000180037000000010000000000000000000000800700003804000001000000";
const GOLDEN_ALL_SERVER_PDUS: &str = "030000130ed0000000000002000800010000000300006802f0807f665e0a0100020101301a020122020102020100020101020100020101020300ffff020102043a000500147c00013214000101010001c0004d63446e24010c1000040008000100000008000000030c0800eb030000020c0c0000000000000000000300000b02f0802e0000010300002202f08068000103eb701480000000ff0310000700000002000000040000000300005902f08068000103eb704b4b001100eb030000000001003800000200000001001800000000000002000000000100000000000000000002001c00200001000100010080073804000001000100000001000000000000000300003802f08068000103eb702a2a001700eb030000000000001800370000000100000000000000000000008007000038040000010000000300002402f08068000103eb701616001700eb0300000000000004001f000000010000000300002802f08068000103eb701a1a001700eb0300000000000008001400000004000000000000000300002802f08068000103eb701a1a001700eb030000000000000800140000000200ea03ea0300000300002802f08068000103eb701a1a001700eb030000000000000800280000000000000003000400";
