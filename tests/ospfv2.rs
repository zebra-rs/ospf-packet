use hex_literal::hex;
use ospf_packet::*;

#[test]
pub fn parse_hello() {
    const PACKET: &[u8] = &hex!(
        "
        02 01 00 2c c0 a8 aa 08 00 00 00 01 27 3b 00 00
        00 00 00 00 00 00 00 00 ff ff ff 00 00 0a 02 01
        00 00 00 28 c0 a8 aa 08 00 00 00 00
        "
    );
    let (rem, packet) = parse(PACKET).unwrap();
    assert!(rem.is_empty());
    println!("{}", packet);
    println!("rem len: {:?}", rem.len());
}

#[test]
pub fn parse_db_desc() {
    const PACKET: &[u8] = &hex!(
        "
        02 02 00 20 c0 a8 aa 08 00 00 00 01 a0 52 00 00
        00 00 00 00 00 00 00 00 05 dc 02 07 41 77 a9 7e
        "
    );
    let (rem, packet) = parse(PACKET).unwrap();
    assert!(rem.is_empty());
    println!("{}", packet);
    println!("rem len: {:?}", rem.len());
}

#[test]
pub fn parse_db_desc_lsa() {
    const PACKET: &[u8] = &hex!(
        "
        02 02 00 ac c0 a8 aa 03 00 00 00 01 f0 67 00 00
        00 00 00 00 00 00 00 00 05 dc 02 02 41 77 a9 7e
        00 01 02 01 c0 a8 aa 03 c0 a8 aa 03 80 00 00 01
        3a 9c 00 30 00 02 02 05 50 d4 10 00 c0 a8 aa 02
        80 00 00 01 2a 49 00 24 00 02 02 05 94 79 ab 00
        c0 a8 aa 02 80 00 00 01 34 a5 00 24 00 02 02 05
        c0 82 78 00 c0 a8 aa 02 80 00 00 01 d3 19 00 24
        00 02 02 05 c0 a8 00 00 c0 a8 aa 02 80 00 00 01
        37 08 00 24 00 02 02 05 c0 a8 01 00 c0 a8 aa 02
        80 00 00 01 2c 12 00 24 00 02 02 05 c0 a8 ac 00
        c0 a8 aa 02 80 00 00 01 33 41 00 24
        "
    );
    let (rem, packet) = parse(PACKET).unwrap();
    assert!(rem.is_empty());
    println!("{}", packet);
    println!("rem len: {:?}", rem.len());
}

#[test]
pub fn parse_ls_request() {
    const PACKET: &[u8] = &hex!(
        "
        02 03 00 24 c0 a8 aa 03 00 00 00 01 bd c7 00 00
        00 00 00 00 00 00 00 00 00 00 00 01 c0 a8 aa 08
        c0 a8 aa 08
        "
    );
    let (rem, packet) = parse(PACKET).unwrap();
    assert!(rem.is_empty());
    println!("{}", packet);
    println!("rem len: {:?}", rem.len());
}

#[test]
pub fn parse_ls_request_multi() {
    const PACKET: &[u8] = &hex!(
        "
        02 03 00 6c c0 a8 aa 08 00 00 00 01 75 95 00 00
        00 00 00 00 00 00 00 00 00 00 00 01 c0 a8 aa 03
        c0 a8 aa 03 00 00 00 05 50 d4 10 00 c0 a8 aa 02
        00 00 00 05 94 79 ab 00 c0 a8 aa 02 00 00 00 05
        c0 82 78 00 c0 a8 aa 02 00 00 00 05 c0 a8 00 00
        c0 a8 aa 02 00 00 00 05 c0 a8 01 00 c0 a8 aa 02
        00 00 00 05 c0 a8 ac 00 c0 a8 aa 02
        "
    );
    let (rem, packet) = parse(PACKET).unwrap();
    assert!(rem.is_empty());
    println!("{}", packet);
    println!("rem len: {:?}", rem.len());
}

#[test]
#[ignore]
pub fn parse_ls_upd() {
    const PACKET: &[u8] = &hex!(
        "
        02 04 00 40 c0 a8 aa 08 00 00 00 01 96 1f 00 00
        00 00 00 00 00 00 00 00 00 00 00 01 03 e2 02 01
        c0 a8 aa 08 c0 a8 aa 08 80 00 0d c3 25 06 00 24
        02 00 00 01 c0 a8 aa 00 ff ff ff 00 03 00 00 0a
        "
    );
    let (rem, packet) = parse(PACKET).unwrap();
    assert_eq!(rem.len(), 0);
    println!("{}", packet);
    println!("rem len: {:?}", rem.len());
}

#[test]
pub fn parse_ls_upd_multi() {
    const PACKET: &[u8] = &hex!(
        "
        02 04 01 24 c0 a8 aa 03 00 00 00 01 36 6b 00 00
        00 00 00 00 00 00 00 00 00 00 00 07 00 02 02 01
        c0 a8 aa 03 c0 a8 aa 03 80 00 00 01 3a 9c 00 30
        02 00 00 02 c0 a8 aa 00 ff ff ff 00 03 00 00 0a
        c0 a8 aa 00 ff ff ff 00 03 00 00 0a 00 03 02 05
        50 d4 10 00 c0 a8 aa 02 80 00 00 01 2a 49 00 24
        ff ff ff ff 80 00 00 14 00 00 00 00 00 00 00 00
        00 03 02 05 94 79 ab 00 c0 a8 aa 02 80 00 00 01
        34 a5 00 24 ff ff ff 00 80 00 00 14 c0 a8 aa 01
        00 00 00 00 00 03 02 05 c0 82 78 00 c0 a8 aa 02
        80 00 00 01 d3 19 00 24 ff ff ff 00 80 00 00 14
        00 00 00 00 00 00 00 00 00 03 02 05 c0 a8 00 00
        c0 a8 aa 02 80 00 00 01 37 08 00 24 ff ff ff 00
        80 00 00 14 00 00 00 00 00 00 00 00 00 03 02 05
        c0 a8 01 00 c0 a8 aa 02 80 00 00 01 2c 12 00 24
        ff ff ff 00 80 00 00 14 00 00 00 00 00 00 00 00
        00 03 02 05 c0 a8 ac 00 c0 a8 aa 02 80 00 00 01
        33 41 00 24 ff ff ff 00 80 00 00 14 c0 a8 aa 0a
        00 00 00 00
        "
    );
    let (rem, packet) = parse(PACKET).unwrap();
    assert_eq!(rem.len(), 0);
    println!("{}", packet);
    println!("rem len: {:?}", rem.len());
}

#[test]
pub fn parse_ls_ack() {
    const PACKET: &[u8] = &hex!(
        "
        02 05 00 2c c0 a8 aa 08 00 00 00 01 02 f2 00 00
        00 00 00 00 00 00 00 00 00 01 02 01 c0 a8 aa 03
        c0 a8 aa 03 80 00 00 02 38 9d 00 30

        "
    );
    let (rem, packet) = parse(PACKET).unwrap();
    assert!(rem.is_empty());
    println!("{}", packet);
    println!("rem len: {:?}", rem.len());
}

#[test]
#[ignore]
pub fn parse_ls_summary() {
    const PACKET: &[u8] = &hex!(
        "
        00 0b 22 03 c0 a8 0a 00 04 04 04 04 80 00 00 01
        1e 7d 00 1c ff ff ff 00 00 00 00 1e
        "
    );
    let (rem, packet) = parse(PACKET).unwrap();
    assert!(rem.is_empty());
    println!("{}", packet);
    println!("rem len: {:?}", rem.len());
}

#[test]
#[ignore]
pub fn parse_lsa_type7() {
    const PACKET: &[u8] = &hex!(
        "
        00 66 28 07 ac 10 00 00 02 02 02 02 80 00 00 01
        63 ac 00 24 ff ff ff fc 80 00 00 64 c0 a8 0a 01
        00 00 00 00
        "
    );
    let (rem, packet) = parse(PACKET).unwrap();
    assert!(rem.is_empty());
    println!("{}", packet);
    println!("rem len: {:?}", rem.len());
}
