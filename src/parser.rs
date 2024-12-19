use std::net::Ipv4Addr;

use bitfield_struct::bitfield;
use byteorder::{BigEndian, ByteOrder};
use bytes::{BufMut, BytesMut};
use internet_checksum::Checksum;
use nom::error::{make_error, ErrorKind};
use nom::number::complete::{be_u24, be_u64, be_u8};
use nom::{Err, IResult};
use nom_derive::*;

use super::util::{many0, Emit, ParseBe};
use super::OspfType;

// OSPF version.
const OSPF_VERSION: u8 = 2;

#[derive(Debug, NomBE)]
pub struct Ospfv2Packet {
    pub version: u8,
    #[nom(Parse = "OspfType::parse")]
    pub typ: OspfType,
    pub len: u16,
    pub router_id: Ipv4Addr,
    pub area_id: Ipv4Addr,
    pub checksum: u16,
    pub auth_type: u16,
    #[nom(Parse = "{ |x| Ospfv2Auth::parse_be(x, auth_type) }")]
    pub auth: Ospfv2Auth,
    #[nom(Parse = "{ |x| Ospfv2Payload::parse_be(x, typ) }")]
    pub payload: Ospfv2Payload,
}

impl Ospfv2Packet {
    pub fn new(router_id: &Ipv4Addr, area_id: &Ipv4Addr, payload: Ospfv2Payload) -> Self {
        Self {
            version: OSPF_VERSION,
            typ: payload.typ(),
            len: 0,
            router_id: *router_id,
            area_id: *area_id,
            checksum: 0,
            auth_type: 0,
            auth: Ospfv2Auth::default(),
            payload,
        }
    }

    pub fn emit(&self, buf: &mut BytesMut) {
        use Ospfv2Payload::*;
        buf.put_u8(self.version);
        buf.put_u8(self.typ.into());
        buf.put_u16(self.len);
        buf.put(&self.router_id.octets()[..]);
        buf.put(&self.area_id.octets()[..]);
        buf.put_u16(0);
        buf.put_u16(self.auth_type);
        self.auth.emit(buf);
        match &self.payload {
            Hello(v) => v.emit(buf),
            DbDesc(v) => v.emit(buf),
            LsRequest(v) => v.emit(buf),
            LsUpdate(v) => v.emit(buf),
            // LsAck(v) => v.emit(buf),
            _ => {}
        }
        // OSPF packet length.
        let len = buf.len() as u16;
        BigEndian::write_u16(&mut buf[2..4], len);

        // Update checksum.
        const CHECKSUM_RANGE: std::ops::Range<usize> = 12..14;
        let mut cksum = Checksum::new();
        cksum.add_bytes(buf);
        buf[CHECKSUM_RANGE].copy_from_slice(&cksum.checksum());
    }
}

#[derive(Debug, Default)]
pub struct Ospfv2Auth {
    pub auth: u64,
}

impl Ospfv2Auth {
    pub fn parse_be(input: &[u8], auth_type: u16) -> IResult<&[u8], Self> {
        if auth_type != 0 {
            return Err(Err::Error(make_error(input, ErrorKind::Tag)));
        }
        let (input, auth) = be_u64(input)?;
        Ok((input, Self { auth }))
    }
}

impl Emit for Ospfv2Auth {
    fn emit(&self, buf: &mut BytesMut) {
        buf.put_u64(self.auth);
    }
}

#[derive(Debug, NomBE)]
#[nom(Selector = "OspfType")]
pub enum Ospfv2Payload {
    #[nom(Selector = "OspfType::Hello")]
    Hello(OspfHello),
    #[nom(Selector = "OspfType::DbDesc")]
    DbDesc(OspfDbDesc),
    #[nom(Selector = "OspfType::LsRequest")]
    LsRequest(OspfLsRequest),
    #[nom(Selector = "OspfType::LsUpdate")]
    LsUpdate(OspfLsUpdate),
    #[nom(Selector = "OspfType::LsAck")]
    LsAck(OspfLsAck),
    #[nom(Selector = "_")]
    Unknown(OspfUnknown),
}

#[derive(Debug)]
pub struct OspfUnknown {
    pub typ: u8,
}

impl OspfUnknown {
    pub fn parse_be(input: &[u8]) -> IResult<&[u8], OspfUnknown> {
        Err(Err::Error(make_error(input, ErrorKind::Verify)))
    }
}

impl Ospfv2Payload {
    pub fn typ(&self) -> OspfType {
        use Ospfv2Payload::*;
        match self {
            Hello(_) => OspfType::Hello,
            DbDesc(_) => OspfType::DbDesc,
            LsRequest(_) => OspfType::LsRequest,
            LsUpdate(_) => OspfType::LsUpdate,
            LsAck(_) => OspfType::LsAck,
            Unknown(_v) => OspfType::Hello,
        }
    }
}

pub fn parse_ipv4addr_vec(input: &[u8]) -> IResult<&[u8], Vec<Ipv4Addr>> {
    many0(Ipv4Addr::parse_be)(input)
}

#[derive(Debug, NomBE)]
pub struct OspfHello {
    pub network_mask: Ipv4Addr,
    pub hello_interval: u16,
    #[nom(Map = "|x: u8| x.into()", Parse = "be_u8")]
    pub options: OspfOptions,
    pub priority: u8,
    pub router_dead_interval: u32,
    pub d_router: Ipv4Addr,
    pub bd_router: Ipv4Addr,
    #[nom(Parse = "parse_ipv4addr_vec")]
    pub neighbors: Vec<Ipv4Addr>,
}

#[bitfield(u8, debug = true)]
#[derive(PartialEq)]
pub struct OspfOptions {
    pub multi_toplogy: bool,
    pub external: bool,
    pub multicast: bool,
    pub nssa: bool,
    pub lls_data: bool,
    pub demand_circuts: bool,
    pub o: bool,
    pub dn: bool,
}

impl Default for OspfHello {
    fn default() -> Self {
        Self {
            network_mask: Ipv4Addr::UNSPECIFIED,
            hello_interval: 0,
            options: OspfOptions(0),
            priority: 0,
            router_dead_interval: 0,
            d_router: Ipv4Addr::UNSPECIFIED,
            bd_router: Ipv4Addr::UNSPECIFIED,
            neighbors: Vec::new(),
        }
    }
}

impl OspfHello {
    pub fn emit(&self, buf: &mut BytesMut) {
        buf.put(&self.network_mask.octets()[..]);
        buf.put_u16(self.hello_interval);
        buf.put_u8(self.options.into());
        buf.put_u8(self.priority);
        buf.put_u32(self.router_dead_interval);
        buf.put(&self.d_router.octets()[..]);
        buf.put(&self.bd_router.octets()[..]);
        for nbr in self.neighbors.iter() {
            buf.put(&nbr.octets()[..]);
        }
    }
}

#[derive(Debug, Default, NomBE, Clone)]
pub struct OspfDbDesc {
    pub if_mtu: u16,
    #[nom(Map = "|x: u8| x.into()", Parse = "be_u8")]
    pub options: OspfOptions,
    #[nom(Map = "|x: u8| x.into()", Parse = "be_u8")]
    pub flags: DbDescFlags,
    pub seqnum: u32,
    pub lsa_headers: Vec<OspfLsaHeader>,
}

#[bitfield(u8, debug = true)]
#[derive(PartialEq)]
pub struct DbDescFlags {
    pub master: bool,
    pub more: bool,
    pub init: bool,
    pub oob_resync: bool,
    #[bits(4)]
    pub resvd: u32,
}

impl DbDescFlags {
    pub fn is_all(&self) -> bool {
        self.master() && self.more() && self.init()
    }
}

impl OspfDbDesc {
    pub fn emit(&self, buf: &mut BytesMut) {
        buf.put_u16(self.if_mtu);
        buf.put_u8(self.options.into());
        buf.put_u8(self.flags.into());
        buf.put_u32(self.seqnum);
        for lsah in self.lsa_headers.iter() {
            lsah.emit(buf);
        }
    }
}

#[derive(Debug, NomBE)]
pub struct OspfLsRequest {
    pub reqs: Vec<OspfLsRequestEntry>,
}

#[derive(Debug, NomBE)]
pub struct OspfLsRequestEntry {
    pub ls_type: u32,
    pub ls_id: u32,
    pub adv_router: Ipv4Addr,
}

impl OspfLsRequest {
    pub fn emit(&self, buf: &mut BytesMut) {
        for req in self.reqs.iter() {
            req.emit(buf);
        }
    }
}

impl OspfLsRequestEntry {
    pub fn emit(&self, buf: &mut BytesMut) {
        buf.put_u32(self.ls_type);
        buf.put_u32(self.ls_id);
        buf.put(&self.adv_router.octets()[..]);
    }
}

#[derive(Debug, NomBE)]
pub struct OspfLsUpdate {
    pub num_adv: u32,
    #[nom(Count = "num_adv")]
    pub lsas: Vec<OspfLsa>,
}

impl OspfLsUpdate {
    pub fn emit(&self, buf: &mut BytesMut) {
        buf.put_u32(self.num_adv);
        for lsa in self.lsas.iter() {
            lsa.emit(buf);
        }
    }
}

#[derive(Debug, NomBE)]
pub struct OspfLsAck {
    pub lsa_headers: Vec<OspfLsaHeader>,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, NomBE)]
pub struct OspfLsType(pub u8);

pub const OSPF_LSA_ROUTER: u8 = 1;
pub const OSPF_LSA_NETWORK: u8 = 2;
pub const OSPF_LSA_SUMMARY_NETWORK: u8 = 3;
pub const OSPF_LSA_SUMMARY_ASBR: u8 = 4;
pub const OSPF_LSA_AS_EXTERNAL: u8 = 5;
pub const OSPF_LSA_NSSA_AS_EXTERNAL: u8 = 7;
pub const OSPF_LSA_OPAQUE_LINK_LOCAL: u8 = 9;
pub const OSPF_LSA_OPAQUE_AREA_LOCAL: u8 = 10;
pub const OSPF_LSA_OPAQUE_AS_WIDE: u8 = 11;

#[derive(Debug, NomBE, Clone)]
pub struct OspfLsaHeader {
    pub ls_age: u16,
    pub options: u8,
    pub ls_type: OspfLsType,
    pub ls_id: u32,
    pub adv_router: Ipv4Addr,
    pub ls_seq_number: u32,
    pub ls_checksum: u16,
    pub length: u16,
}

impl OspfLsaHeader {
    pub fn emit(&self, buf: &mut BytesMut) {
        buf.put_u16(self.ls_age);
        buf.put_u8(self.options);
        buf.put_u8(self.ls_type.0);
        buf.put_u32(self.ls_id);
        buf.put(&self.adv_router.octets()[..]);
        buf.put_u32(self.ls_seq_number);
        buf.put_u16(self.ls_checksum);
        buf.put_u16(self.length);
    }
}

#[derive(Debug, NomBE)]
pub struct OspfLsa {
    pub h: OspfLsaHeader,
    #[nom(Parse = "{ |x| OspfLsaPayload::parse_lsa(x, h.ls_type) }")]
    pub lsa: OspfLsaPayload,
}

impl Emit for OspfLsa {
    fn emit(&self, buf: &mut BytesMut) {
        self.h.emit(buf);
    }
}

#[derive(Debug, NomBE)]
#[nom(Selector = "OspfLsType")]
pub enum OspfLsaPayload {
    #[nom(Selector = "OspfLsType(OSPF_LSA_ROUTER)")]
    Router(RouterLsa),
    #[nom(Selector = "OspfLsType(OSPF_LSA_NETWORK)")]
    Network(NetworkLsa),
    // Summary(SummaryLsa),
    // SummaryAsbr(SummaryAsbrLsa),
    #[nom(Selector = "OspfLsType(OSPF_LSA_AS_EXTERNAL)")]
    AsExternal(AsExternalLsa),
    // NssaAsExternal(NssaAsExternalLsa),
    // OpaqueLink(OpaqueLinkLsa),
    // OpaqueArea(OpaqueAreaLsa),
    // OpaqueAs(OpaqueAsLsa),
    #[nom(Selector = "OspfLsType(_)")]
    Unknown(UnknownLsa),
}

impl OspfLsaPayload {
    pub fn parse_lsa(input: &[u8], typ: OspfLsType) -> IResult<&[u8], Self> {
        OspfLsaPayload::parse_be(input, typ)
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, NomBE)]
pub struct OspfRouterLinkType(pub u8);

#[derive(Debug, NomBE)]
pub struct OspfRouterTOS {
    pub tos: u8,
    pub resved: u8,
    pub metric: u16,
}

#[derive(Debug, NomBE)]
pub struct RouterLsa {
    pub flags: u16,
    pub num_links: u16,
    #[nom(Count = "num_links")]
    pub links: Vec<RouterLsaLink>,
}

#[derive(Debug, NomBE)]
pub struct RouterLsaLink {
    pub link_id: Ipv4Addr,
    pub link_data: Ipv4Addr,
    pub link_type: OspfRouterLinkType,
    pub num_tos: u8,
    pub tos_0_metric: u16,
    #[nom(Count = "num_tos")]
    pub toses: Vec<OspfRouterTOS>,
}

#[derive(Debug, NomBE)]
pub struct NetworkLsa {
    pub network_mask: Ipv4Addr,
    pub attached_routers: Vec<u32>,
}

#[derive(Debug, NomBE)]
pub struct AsExternalLsa {
    pub network_mask: Ipv4Addr,
    pub ext_and_resvd: u8,
    #[nom(Parse = "be_u24")]
    pub metric: u32,
    pub forwarding_address: Ipv4Addr,
    pub external_route_tag: u32,
}

#[derive(Debug, NomBE)]
pub struct UnknownLsa {
    pub data: Vec<u8>,
}

pub fn validate_checksum(input: &[u8]) -> IResult<&[u8], ()> {
    const AUTH_RANGE: std::ops::Range<usize> = 16..24;

    let mut cksum = Checksum::new();
    cksum.add_bytes(&input[0..AUTH_RANGE.start]);
    cksum.add_bytes(&input[AUTH_RANGE.end..]);
    if cksum.checksum() != [0; 2] {
        Err(Err::Error(make_error(input, ErrorKind::Verify)))
    } else {
        Ok((input, ()))
    }
}

pub fn parse(input: &[u8]) -> IResult<&[u8], Ospfv2Packet> {
    validate_checksum(input)?;
    let (input, packet) = Ospfv2Packet::parse_be(input)?;
    Ok((input, packet))
}
