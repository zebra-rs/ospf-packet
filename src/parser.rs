use std::net::Ipv4Addr;

use nom::error::{make_error, ErrorKind};
use nom::number::complete::{be_u24, be_u64};
use nom::{Err, IResult};
use nom_derive::*;

use crate::util::ParseBe;

// OSPF packet types.
const OSPF_HELLO: u8 = 1;
const OSPF_DATABASE_DESC: u8 = 2;
const OSPF_LINK_STATE_REQUEST: u8 = 3;
const OSPF_LINK_STATE_UPDATE: u8 = 4;
const OSPF_LINK_STATE_ACK: u8 = 5;

// OSPF packet types.
#[derive(Debug, PartialEq, Eq, Clone, Copy, NomBE)]
pub struct OspfPacketType(pub u8);

#[derive(Debug, NomBE)]
pub struct Ospfv2Packet {
    pub version: u8,
    pub typ: OspfPacketType,
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

#[derive(Debug)]
pub struct Ospfv2Auth {
    pub auth: u64,
}

impl Ospfv2Auth {
    pub fn parse_be(input: &[u8], auth_type: u16) -> IResult<&[u8], Self> {
        // XXX only handle auth_type is zero.
        if auth_type != 0 {
            return Err(Err::Error(make_error(input, ErrorKind::Tag)));
        }
        let (input, auth) = be_u64(input)?;
        Ok((input, Self { auth }))
    }
}

#[derive(Debug, NomBE)]
#[nom(Selector = "OspfPacketType")]
pub enum Ospfv2Payload {
    #[nom(Selector = "OspfPacketType(OSPF_HELLO)")]
    Hello(OspfHello),
    #[nom(Selector = "OspfPacketType(OSPF_DATABASE_DESC)")]
    DbDesc(OspfDbDesc),
    #[nom(Selector = "OspfPacketType(OSPF_LINK_STATE_REQUEST)")]
    LsRequest(OspfLsRequest),
    #[nom(Selector = "OspfPacketType(OSPF_LINK_STATE_UPDATE)")]
    LsUpdate(OspfLsUpdate),
    #[nom(Selector = "OspfPacketType(OSPF_LINK_STATE_ACK)")]
    LsAck(OspfLsAck),
}

#[derive(Debug, NomBE)]
pub struct OspfHello {
    pub network_mask: Ipv4Addr,
    pub hello_interval: u16,
    pub options: u8,
    pub router_priority: u8,
    pub router_dead_interval: u32,
    pub designated_router: Ipv4Addr,
    pub backup_designated_router: Ipv4Addr,
}

#[derive(Debug, NomBE)]
pub struct OspfDbDesc {
    pub if_mtu: u16,
    pub options: u8,
    pub flags: u8,
    pub dd_seq_number: u32,
    pub lsa_headers: Vec<OspfLsaHeader>,
}

#[derive(Debug, NomBE)]
pub struct OspfLsRequestEntry {
    pub ls_type: u32,
    pub ls_id: u32,
    pub adv_router: Ipv4Addr,
}

#[derive(Debug, NomBE)]
pub struct OspfLsRequest {
    pub reqs: Vec<OspfLsRequestEntry>,
}

#[derive(Debug, NomBE)]
pub struct OspfLsUpdate {
    pub num_adv: u32,
    #[nom(Count = "num_adv")]
    pub lsas: Vec<OspfLsa>,
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
pub const OPSF_LSA_OPAQUE_LINK_LOCAL: u8 = 9;
pub const OSPF_LSA_OPAQUE_AREA_LOCAL: u8 = 10;
pub const OSPF_LSA_OPAQUE_AS_WIDE: u8 = 11;

#[derive(Debug, NomBE)]
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

#[derive(Debug, NomBE)]
pub struct OspfLsa {
    pub h: OspfLsaHeader,
    #[nom(Parse = "{ |x| OspfLsaPayload::parse_lsa(x, h.ls_type) }")]
    pub lsa: OspfLsaPayload,
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
        println!("XX LSA Type {:?}", typ.0);
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

pub fn parse(input: &[u8]) -> IResult<&[u8], Ospfv2Packet> {
    let (input, packet) = Ospfv2Packet::parse_be(input)?;
    Ok((input, packet))
}
