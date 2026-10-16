//! Generate a synthetic capture with real problems planted in it.
//!
//! `cargo run -p transit_pcap --example synth_capture -- /tmp/lab.pcap`
//!
//! Exists for smoke-testing the PCaps surface without needing a lab or a
//! privileged capture: it produces a file that exercises the packet list,
//! the dissectors, the filter language, and — the point — every findings
//! rule that matters, so the Findings tab is populated on first open
//! rather than empty.
//!
//! Written with the crate's own writer from the same RFC field layouts
//! the corpus uses. We ship no third-party sample captures (plan §11).

use transit_pcap::types::LinkType;
use transit_pcap::writer::PcapWriter;

const SRC_MAC: [u8; 6] = [0x00, 0x1b, 0x21, 0x3c, 0x4d, 0x5e];
const DST_MAC: [u8; 6] = [0x00, 0x50, 0x56, 0xaa, 0xbb, 0xcc];

fn eth(ethertype: u16, payload: &[u8]) -> Vec<u8> {
    let mut p = Vec::with_capacity(14 + payload.len());
    p.extend_from_slice(&DST_MAC);
    p.extend_from_slice(&SRC_MAC);
    p.extend_from_slice(&ethertype.to_be_bytes());
    p.extend_from_slice(payload);
    p
}

fn ipv4(proto: u8, src: [u8; 4], dst: [u8; 4], payload: &[u8]) -> Vec<u8> {
    let total = 20 + payload.len();
    let mut p = Vec::with_capacity(total);
    p.extend_from_slice(&[0x45, 0x00]);
    p.extend_from_slice(&(total as u16).to_be_bytes());
    p.extend_from_slice(&[0x00, 0x01]);
    p.extend_from_slice(&[0x40, 0x00]); // DF set
    p.push(64);
    p.push(proto);
    p.extend_from_slice(&[0, 0]);
    p.extend_from_slice(&src);
    p.extend_from_slice(&dst);
    p.extend_from_slice(payload);
    p
}

#[allow(clippy::too_many_arguments)]
fn tcp(
    sport: u16,
    dport: u16,
    flags: u8,
    seq: u32,
    ack: u32,
    window: u16,
    payload: &[u8],
) -> Vec<u8> {
    let mut p = Vec::with_capacity(20 + payload.len());
    p.extend_from_slice(&sport.to_be_bytes());
    p.extend_from_slice(&dport.to_be_bytes());
    p.extend_from_slice(&seq.to_be_bytes());
    p.extend_from_slice(&ack.to_be_bytes());
    p.push(0x50);
    p.push(flags);
    p.extend_from_slice(&window.to_be_bytes());
    p.extend_from_slice(&[0, 0, 0, 0]);
    p.extend_from_slice(payload);
    p
}

fn udp(sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    let mut p = Vec::with_capacity(8 + payload.len());
    p.extend_from_slice(&sport.to_be_bytes());
    p.extend_from_slice(&dport.to_be_bytes());
    p.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    p.extend_from_slice(&[0, 0]);
    p.extend_from_slice(payload);
    p
}

fn dns(id: u16, name: &str, response: bool, rcode: u8) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(&id.to_be_bytes());
    let flags: u16 = if response {
        0x8180 | u16::from(rcode)
    } else {
        0x0100
    };
    p.extend_from_slice(&flags.to_be_bytes());
    p.extend_from_slice(&1u16.to_be_bytes());
    p.extend_from_slice(&[0, 0, 0, 0, 0, 0]);
    for label in name.split('.') {
        p.push(label.len() as u8);
        p.extend_from_slice(label.as_bytes());
    }
    p.push(0);
    p.extend_from_slice(&1u16.to_be_bytes());
    p.extend_from_slice(&1u16.to_be_bytes());
    p
}

const TCP_FIN: u8 = 0x01;
const TCP_SYN: u8 = 0x02;
const TCP_RST: u8 = 0x04;
const TCP_ACK: u8 = 0x10;

fn main() {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "/tmp/transit-synth.pcap".to_string());
    let path = std::path::PathBuf::from(path);
    let mut w = PcapWriter::create(&path, LinkType::Ethernet, 262_144).expect("create capture");

    let mut t: i64 = 1_785_000_000_000_000;
    let push = |w: &mut PcapWriter<_>, frame: Vec<u8>, dt: i64, t: &mut i64| {
        *t += dt;
        w.write_packet(*t, frame.len() as u32, &frame).unwrap();
    };

    // ---- A healthy conversation, so the capture is not all problems ----
    let client = [10, 10, 20, 14];
    let server = [10, 10, 20, 80];
    push(
        &mut w,
        eth(
            0x0800,
            &ipv4(
                6,
                client,
                server,
                &tcp(52344, 443, TCP_SYN, 1000, 0, 65535, &[]),
            ),
        ),
        1_000,
        &mut t,
    );
    push(
        &mut w,
        eth(
            0x0800,
            &ipv4(
                6,
                server,
                client,
                &tcp(443, 52344, TCP_SYN | TCP_ACK, 5000, 1001, 65535, &[]),
            ),
        ),
        11_200,
        &mut t,
    );
    push(
        &mut w,
        eth(
            0x0800,
            &ipv4(
                6,
                client,
                server,
                &tcp(52344, 443, TCP_ACK, 1001, 5001, 65535, &[]),
            ),
        ),
        400,
        &mut t,
    );
    for i in 0..120u32 {
        push(
            &mut w,
            eth(
                0x0800,
                &ipv4(
                    6,
                    client,
                    server,
                    &tcp(
                        52344,
                        443,
                        TCP_ACK,
                        1001 + i * 1400,
                        5001,
                        65535,
                        &[0u8; 1400],
                    ),
                ),
            ),
            900,
            &mut t,
        );
        push(
            &mut w,
            eth(
                0x0800,
                &ipv4(
                    6,
                    server,
                    client,
                    &tcp(443, 52344, TCP_ACK, 5001, 1001 + (i + 1) * 1400, 65535, &[]),
                ),
            ),
            10_800,
            &mut t,
        );
    }

    // ---- A conversation losing packets: same bytes sent twice ----
    let lossy = [10, 10, 20, 30];
    push(
        &mut w,
        eth(
            0x0800,
            &ipv4(
                6,
                lossy,
                server,
                &tcp(41000, 443, TCP_SYN, 900, 0, 65535, &[]),
            ),
        ),
        2_000,
        &mut t,
    );
    push(
        &mut w,
        eth(
            0x0800,
            &ipv4(
                6,
                server,
                lossy,
                &tcp(443, 41000, TCP_SYN | TCP_ACK, 7000, 901, 65535, &[]),
            ),
        ),
        40_000,
        &mut t,
    );
    for i in 0..100u32 {
        let seq = 901 + i * 1400;
        push(
            &mut w,
            eth(
                0x0800,
                &ipv4(
                    6,
                    lossy,
                    server,
                    &tcp(41000, 443, TCP_ACK, seq, 7001, 65535, &[0u8; 1400]),
                ),
            ),
            1_000,
            &mut t,
        );
        // Every third segment is sent again — a real retransmission.
        if i % 3 == 0 {
            push(
                &mut w,
                eth(
                    0x0800,
                    &ipv4(
                        6,
                        lossy,
                        server,
                        &tcp(41000, 443, TCP_ACK, seq, 7001, 65535, &[0u8; 1400]),
                    ),
                ),
                220_000,
                &mut t,
            );
        }
    }

    // ---- An MTU black hole: frag-needed, DF set, next-hop MTU 1400 ----
    for _ in 0..12 {
        let mut icmp = vec![3u8, 4, 0, 0, 0, 0];
        icmp.extend_from_slice(&1400u16.to_be_bytes());
        icmp.extend_from_slice(&[0u8; 28]);
        push(
            &mut w,
            eth(0x0800, &ipv4(1, [10, 10, 20, 1], client, &icmp)),
            30_000,
            &mut t,
        );
    }

    // ---- A receiver that stops reading: a 3.2s zero-window stall ----
    let stalled = [10, 10, 20, 55];
    push(
        &mut w,
        eth(
            0x0800,
            &ipv4(
                6,
                stalled,
                server,
                &tcp(44000, 443, TCP_SYN, 100, 0, 65535, &[]),
            ),
        ),
        5_000,
        &mut t,
    );
    push(
        &mut w,
        eth(
            0x0800,
            &ipv4(
                6,
                server,
                stalled,
                &tcp(443, 44000, TCP_SYN | TCP_ACK, 8000, 101, 65535, &[]),
            ),
        ),
        9_000,
        &mut t,
    );
    push(
        &mut w,
        eth(
            0x0800,
            &ipv4(
                6,
                stalled,
                server,
                &tcp(44000, 443, TCP_ACK, 101, 8001, 0, &[]),
            ),
        ),
        1_000,
        &mut t,
    );
    push(
        &mut w,
        eth(
            0x0800,
            &ipv4(
                6,
                stalled,
                server,
                &tcp(44000, 443, TCP_ACK, 101, 8001, 0, &[]),
            ),
        ),
        3_200_000,
        &mut t,
    );

    // ---- A refused connection, and one nobody answered ----
    push(
        &mut w,
        eth(
            0x0800,
            &ipv4(
                6,
                client,
                [10, 10, 20, 99],
                &tcp(52400, 8080, TCP_SYN, 1, 0, 65535, &[]),
            ),
        ),
        4_000,
        &mut t,
    );
    push(
        &mut w,
        eth(
            0x0800,
            &ipv4(
                6,
                [10, 10, 20, 99],
                client,
                &tcp(8080, 52400, TCP_RST | TCP_ACK, 0, 2, 0, &[]),
            ),
        ),
        900,
        &mut t,
    );
    push(
        &mut w,
        eth(
            0x0800,
            &ipv4(
                6,
                client,
                [10, 10, 20, 200],
                &tcp(52401, 22, TCP_SYN, 1, 0, 65535, &[]),
            ),
        ),
        4_000,
        &mut t,
    );

    // ---- DNS: some working, several NXDOMAIN, several unanswered ----
    let resolver = [10, 10, 20, 53];
    for (i, name) in ["www.example.com", "api.internal.corp", "cdn.example.net"]
        .iter()
        .enumerate()
    {
        let id = 0x1000 + i as u16;
        push(
            &mut w,
            eth(
                0x0800,
                &ipv4(
                    17,
                    client,
                    resolver,
                    &udp(51234, 53, &dns(id, name, false, 0)),
                ),
            ),
            3_000,
            &mut t,
        );
        push(
            &mut w,
            eth(
                0x0800,
                &ipv4(
                    17,
                    resolver,
                    client,
                    &udp(53, 51234, &dns(id, name, true, 0)),
                ),
            ),
            8_000,
            &mut t,
        );
    }
    for i in 0..8u16 {
        let name = format!("missing{i}.example.com");
        let id = 0x2000 + i;
        push(
            &mut w,
            eth(
                0x0800,
                &ipv4(
                    17,
                    client,
                    resolver,
                    &udp(51235, 53, &dns(id, &name, false, 0)),
                ),
            ),
            2_000,
            &mut t,
        );
        push(
            &mut w,
            eth(
                0x0800,
                &ipv4(
                    17,
                    resolver,
                    client,
                    &udp(53, 51235, &dns(id, &name, true, 3)),
                ),
            ),
            6_000,
            &mut t,
        );
    }
    for i in 0..7u16 {
        let name = format!("silent{i}.example.com");
        push(
            &mut w,
            eth(
                0x0800,
                &ipv4(
                    17,
                    client,
                    resolver,
                    &udp(51236, 53, &dns(0x3000 + i, &name, false, 0)),
                ),
            ),
            2_000,
            &mut t,
        );
    }

    // ---- Two hosts claiming one address ----
    for mac in [[0xaa; 6], [0xbb; 6]] {
        let mut arp = Vec::new();
        arp.extend_from_slice(&1u16.to_be_bytes());
        arp.extend_from_slice(&0x0800u16.to_be_bytes());
        arp.push(6);
        arp.push(4);
        arp.extend_from_slice(&2u16.to_be_bytes());
        arp.extend_from_slice(&mac);
        arp.extend_from_slice(&[10, 10, 20, 50]);
        arp.extend_from_slice(&[0u8; 6]);
        arp.extend_from_slice(&[10, 10, 20, 1]);
        push(&mut w, eth(0x0806, &arp), 15_000, &mut t);
    }

    // ---- Cleartext HTTP carrying a credential (redacted on the way out) ----
    let req = "GET /admin HTTP/1.1\r\nHost: box.internal\r\n\
               Authorization: Basic YWRtaW46aHVudGVyMg==\r\n\
               User-Agent: curl/8.4.0\r\n\r\n";
    push(
        &mut w,
        eth(
            0x0800,
            &ipv4(
                6,
                client,
                [10, 10, 20, 8],
                &tcp(52500, 80, TCP_ACK, 1, 1, 65535, req.as_bytes()),
            ),
        ),
        6_000,
        &mut t,
    );
    let resp = "HTTP/1.1 500 Internal Server Error\r\nServer: nginx\r\n\r\n";
    for _ in 0..6 {
        push(
            &mut w,
            eth(
                0x0800,
                &ipv4(
                    6,
                    [10, 10, 20, 8],
                    client,
                    &tcp(80, 52500, TCP_ACK, 1, 200, 65535, resp.as_bytes()),
                ),
            ),
            12_000,
            &mut t,
        );
    }

    // ---- A TLS handshake the server rejected ----
    let mut alert = vec![21u8, 0x03, 0x03];
    alert.extend_from_slice(&2u16.to_be_bytes());
    alert.extend_from_slice(&[2, 40]); // fatal, handshake_failure
    push(
        &mut w,
        eth(
            0x0800,
            &ipv4(
                6,
                server,
                client,
                &tcp(443, 52344, TCP_ACK, 9000, 2000, 65535, &alert),
            ),
        ),
        7_000,
        &mut t,
    );

    push(
        &mut w,
        eth(
            0x0800,
            &ipv4(
                6,
                client,
                server,
                &tcp(52344, 443, TCP_FIN | TCP_ACK, 200_000, 5001, 65535, &[]),
            ),
        ),
        5_000,
        &mut t,
    );

    w.finish().expect("finish capture");
    println!("wrote {}", path.display());
    println!();
    println!("Planted for the Findings tab:");
    println!("  high  MTU black hole          — 12 x frag-needed, next-hop MTU 1400");
    println!("  high  zero-window stall       — 10.10.20.55 stalled 3.2s");
    println!("  high  connection unanswered   — SYN to 10.10.20.200:22, no reply");
    println!("  high  duplicate IP address    — 10.10.20.50 claimed by two MACs");
    println!("  high  DNS unanswered          — 7 queries with no response");
    println!("  high  TLS fatal alert         — handshake_failure");
    println!("  med   TCP retransmission      — 10.10.20.30 losing ~25%");
    println!("  med   connection refused      — RST from 10.10.20.99:8080");
    println!("  med   DNS failure rate        — 8 NXDOMAIN of 11 responses");
    println!("  med   HTTP server errors      — 6 x 500");
    println!("  med   cleartext credentials   — Basic auth (value redacted)");
}
