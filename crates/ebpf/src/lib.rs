//! Snitchhiker's eBPF programs, embedded in the binary, and their loader.
//!
//! The programs (in `bpf/`, `GPL-2.0-only OR MIT`) record, for every new TCP connection and UDP flow, which process
//! opened it, keyed by the flow; [`Attribution::owner`] looks a queued packet's flow up. The hooks run before the
//! flow's first packet leaves, so its owner is known by the time the packet is queued.

use std::net::IpAddr;

use aya::maps::{HashMap, MapData};
use aya::programs::FEntry;
use aya::{Btf, Ebpf};

/// The compiled programs (`build.rs`), aligned as the ELF parser needs.
static ATTRIBUTION: &[u8] =
    aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/attribution.bpf.o"));

/// Each program and the kernel function it is attached to.
const HOOKS: &[(&str, &str)] = &[
    ("on_tcp_connect", "tcp_connect"),
    ("on_udp_sendmsg", "udp_sendmsg"),
    ("on_udpv6_sendmsg", "udpv6_sendmsg"),
];

const AF_INET: u8 = 2;
const AF_INET6: u8 = 10;
const KEY_LEN: usize = 28;
const OWNER_LEN: usize = 48;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("loading the eBPF object: {0}")]
    Load(#[from] aya::EbpfError),
    #[error("reading the kernel's BTF: {0}")]
    Btf(#[from] aya::BtfError),
    #[error("program {program}: {source}")]
    Program {
        program: &'static str,
        source: aya::programs::ProgramError,
    },
    #[error("map {map}: {source}")]
    Map {
        map: &'static str,
        source: aya::maps::MapError,
    },
    #[error("the object has no {0}")]
    Missing(&'static str),
}

/// A flow as its first packet identifies it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FlowKey {
    /// The inode number of the sending socket's network namespace.
    pub netns: u32,
    /// `IPPROTO_TCP` or `IPPROTO_UDP`.
    pub protocol: u8,
    pub source_port: u16,
    pub destination: IpAddr,
    pub destination_port: u16,
}

impl FlowKey {
    /// The key as the programs store it: `struct flow_key`, in the machine's byte order.
    #[must_use]
    pub fn encode(&self) -> [u8; KEY_LEN] {
        let mut key = [0_u8; KEY_LEN];
        let (family, address) = match self.destination {
            IpAddr::V4(address) => {
                let mut bytes = [0_u8; 16];
                if let Some(head) = bytes.get_mut(..4) {
                    head.copy_from_slice(&address.octets());
                }
                (AF_INET, bytes)
            }
            IpAddr::V6(address) => (AF_INET6, address.octets()),
        };
        let fields: [&[u8]; 7] = [
            &self.netns.to_ne_bytes(),
            &[self.protocol],
            &[family],
            &self.source_port.to_ne_bytes(),
            &self.destination_port.to_ne_bytes(),
            &[0, 0],
            &address,
        ];
        let mut offset = 0;
        for field in fields {
            if let Some(target) = key.get_mut(offset..offset + field.len()) {
                target.copy_from_slice(field);
            }
            offset += field.len();
        }
        key
    }
}

/// Who opened a flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlowOwner {
    pub cgroup: u64,
    /// `CLOCK_MONOTONIC` nanoseconds when the flow was recorded.
    pub ktime: u64,
    /// The process (thread group) id.
    pub pid: u32,
    /// The thread id.
    pub tid: u32,
    pub uid: u32,
    pub gid: u32,
    /// The thread's name, NUL-padded.
    pub comm: [u8; 16],
}

impl FlowOwner {
    fn decode(bytes: &[u8; OWNER_LEN]) -> Self {
        let u64_at = |at: usize| {
            bytes
                .get(at..at + 8)
                .and_then(|b| b.try_into().ok())
                .map_or(0, u64::from_ne_bytes)
        };
        let u32_at = |at: usize| {
            bytes
                .get(at..at + 4)
                .and_then(|b| b.try_into().ok())
                .map_or(0, u32::from_ne_bytes)
        };
        let mut comm = [0_u8; 16];
        if let Some(source) = bytes.get(32..48) {
            comm.copy_from_slice(source);
        }
        Self {
            cgroup: u64_at(0),
            ktime: u64_at(8),
            pid: u32_at(16),
            tid: u32_at(20),
            uid: u32_at(24),
            gid: u32_at(28),
            comm,
        }
    }

    /// The thread's name, up to its first NUL.
    #[must_use]
    pub fn comm(&self) -> &[u8] {
        let end = self
            .comm
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(self.comm.len());
        self.comm.get(..end).unwrap_or_default()
    }
}

/// The attribution programs, loaded and attached for as long as this lives.
pub struct Attribution {
    flows: HashMap<MapData, [u8; KEY_LEN], [u8; OWNER_LEN]>,
    _ebpf: Ebpf,
}

impl Attribution {
    /// Loads the programs (fitting them to the running kernel's BTF) and attaches them.
    pub fn load() -> Result<Self, Error> {
        let mut ebpf = Ebpf::load(ATTRIBUTION)?;
        let btf = Btf::from_sys_fs()?;
        for &(program, function) in HOOKS {
            let hook: &mut FEntry = ebpf
                .program_mut(program)
                .ok_or(Error::Missing(program))?
                .try_into()
                .map_err(|source| Error::Program { program, source })?;
            hook.load(function, &btf)
                .map_err(|source| Error::Program { program, source })?;
            hook.attach()
                .map_err(|source| Error::Program { program, source })?;
        }
        let map = ebpf.take_map("flows").ok_or(Error::Missing("flows"))?;
        let flows = HashMap::try_from(map).map_err(|source| Error::Map {
            map: "flows",
            source,
        })?;
        Ok(Self { flows, _ebpf: ebpf })
    }

    /// The owner of a flow, if the programs saw it open.
    #[must_use]
    pub fn owner(&self, key: &FlowKey) -> Option<FlowOwner> {
        self.flows
            .get(&key.encode(), 0)
            .ok()
            .map(|owner| FlowOwner::decode(&owner))
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;

    #[test]
    fn keys_have_the_c_layout() {
        let key = FlowKey {
            netns: 0x0102_0304,
            protocol: 6,
            source_port: 0x0a0b,
            destination: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 7)),
            destination_port: 443,
        };
        let bytes = key.encode();
        assert_eq!(&bytes[0..4], &0x0102_0304_u32.to_ne_bytes());
        assert_eq!(&bytes[4..6], &[6, AF_INET]);
        assert_eq!(&bytes[6..8], &0x0a0b_u16.to_ne_bytes());
        assert_eq!(&bytes[8..10], &443_u16.to_ne_bytes());
        assert_eq!(&bytes[10..12], &[0, 0]);
        assert_eq!(&bytes[12..16], &[198, 51, 100, 7]);
        assert!(bytes[16..].iter().all(|&b| b == 0));
    }

    #[test]
    fn ipv6_keys_carry_the_whole_address() {
        let key = FlowKey {
            netns: 1,
            protocol: 17,
            source_port: 1,
            destination: IpAddr::V6(Ipv6Addr::LOCALHOST),
            destination_port: 53,
        };
        let bytes = key.encode();
        assert_eq!(bytes[5], AF_INET6);
        assert_eq!(&bytes[12..], &Ipv6Addr::LOCALHOST.octets());
    }

    #[test]
    fn owners_decode_the_c_layout() {
        let mut bytes = [0_u8; OWNER_LEN];
        bytes[16..20].copy_from_slice(&42_u32.to_ne_bytes());
        bytes[24..28].copy_from_slice(&1001_u32.to_ne_bytes());
        bytes[32..36].copy_from_slice(b"curl");
        let owner = FlowOwner::decode(&bytes);
        assert_eq!(owner.pid, 42);
        assert_eq!(owner.uid, 1001);
        assert_eq!(owner.comm(), b"curl");
    }
}
