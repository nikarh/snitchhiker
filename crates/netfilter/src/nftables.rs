//! Snitchhiker's `nf_tables` tables, written as netlink batches: the daemon's (which queues new connections to it),
//! and the system firewall's (the base packet filter the user configures).
//!
//! Only our own table is ever created, changed, read or deleted: nothing here lists the ruleset or touches another
//! table, so another firewall's large sets cost us nothing (a lesson from libnftables, which reads every interval set
//! of every table before adding a set element).

use crate::netlink::{
    AF_UNSPEC, NFNL_MSG_BATCH_BEGIN, NFNL_MSG_BATCH_END, NFNL_SUBSYS_NFTABLES, NFPROTO_INET,
    NLM_F_ACK, NLM_F_APPEND, NLM_F_CREATE, Writer,
};

const NFT_MSG_NEWTABLE: u16 = 0;
const NFT_MSG_DELTABLE: u16 = 2;
const NFT_MSG_NEWCHAIN: u16 = 3;
const NFT_MSG_NEWRULE: u16 = 6;

const NFTA_TABLE_NAME: u16 = 1;

const NFTA_CHAIN_TABLE: u16 = 1;
const NFTA_CHAIN_NAME: u16 = 3;
const NFTA_CHAIN_HOOK: u16 = 4;
const NFTA_CHAIN_POLICY: u16 = 5;
const NFTA_CHAIN_TYPE: u16 = 7;
const NFTA_HOOK_HOOKNUM: u16 = 1;
const NFTA_HOOK_PRIORITY: u16 = 2;

const NFTA_RULE_TABLE: u16 = 1;
const NFTA_RULE_CHAIN: u16 = 2;
const NFTA_RULE_EXPRESSIONS: u16 = 4;
const NFTA_LIST_ELEM: u16 = 1;
const NFTA_EXPR_NAME: u16 = 1;
const NFTA_EXPR_DATA: u16 = 2;

const NFTA_DATA_VALUE: u16 = 1;
const NFTA_DATA_VERDICT: u16 = 2;
const NFTA_VERDICT_CODE: u16 = 1;

const NFTA_META_DREG: u16 = 1;
const NFTA_META_KEY: u16 = 2;
const NFT_META_MARK: u32 = 3;
const NFT_META_L4PROTO: u32 = 16;

const NFTA_CMP_SREG: u16 = 1;
const NFTA_CMP_OP: u16 = 2;
const NFTA_CMP_DATA: u16 = 3;
const NFT_CMP_EQ: u32 = 0;
const NFT_CMP_NEQ: u32 = 1;

const NFTA_BITWISE_SREG: u16 = 1;
const NFTA_BITWISE_DREG: u16 = 2;
const NFTA_BITWISE_LEN: u16 = 3;
const NFTA_BITWISE_MASK: u16 = 4;
const NFTA_BITWISE_XOR: u16 = 5;

const NFTA_PAYLOAD_DREG: u16 = 1;
const NFTA_PAYLOAD_BASE: u16 = 2;
const NFTA_PAYLOAD_OFFSET: u16 = 3;
const NFTA_PAYLOAD_LEN: u16 = 4;
const NFT_PAYLOAD_TRANSPORT_HEADER: u32 = 2;

const NFTA_CT_DREG: u16 = 1;
const NFTA_CT_KEY: u16 = 2;
const NFT_CT_STATE: u32 = 0;
const CT_STATE_RELATED: u32 = 1 << 2;
const CT_STATE_NEW: u32 = 1 << 3;

const NFTA_IMMEDIATE_DREG: u16 = 1;
const NFTA_IMMEDIATE_DATA: u16 = 2;

const NFTA_QUEUE_NUM: u16 = 1;
const NFTA_QUEUE_TOTAL: u16 = 2;
const NFTA_QUEUE_FLAGS: u16 = 3;
const NFT_QUEUE_FLAG_BYPASS: u16 = 0x01;

const NFT_REG_VERDICT: u32 = 0;
const NFT_REG_1: u32 = 1;

const NF_DROP: u32 = 0;
const NF_ACCEPT: u32 = 1;
const NF_INET_LOCAL_IN: u32 = 1;
const NF_INET_FORWARD: u32 = 2;
const NF_INET_LOCAL_OUT: u32 = 3;
const NF_IP_PRI_MANGLE: i32 = -150;
const NF_IP_PRI_FILTER: i32 = 0;

const NFT_META_NFPROTO: u32 = 15;
const NFT_META_IIFNAME: u32 = 6;
const NFT_META_OIFNAME: u32 = 7;
const NFPROTO_IPV4: u8 = 2;
const NFPROTO_IPV6: u8 = 10;
const NFT_PAYLOAD_NETWORK_HEADER: u32 = 1;
const NFT_CMP_LTE: u32 = 3;
const NFT_CMP_GTE: u32 = 5;
/// Interface names are this long in the kernel, with the terminating zero.
const IFNAMSIZ: usize = 16;

const NFTA_REJECT_TYPE: u16 = 1;
const NFTA_REJECT_ICMP_CODE: u16 = 2;
const NFT_REJECT_TCP_RST: u32 = 1;
const NFT_REJECT_ICMPX_UNREACH: u32 = 2;
const NFT_REJECT_ICMPX_PORT_UNREACH: u8 = 1;
const NFTA_LOG_PREFIX: u16 = 2;

const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
const DNS_PORT: u16 = 53;
/// The TCP flags byte of the header, and the flags `nft`'s `tcp flags & (fin|syn|rst|ack) == syn` looks at.
const TCP_FLAGS_OFFSET: u32 = 13;
const TCP_FIN_SYN_RST_ACK: u8 = 0x01 | 0x02 | 0x04 | 0x10;
const TCP_SYN: u8 = 0x02;

/// What the daemon's table looks like.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Table {
    pub name: String,
    /// The first NFQUEUE number new flows are queued to.
    pub queue: u16,
    /// How many queues, from `queue` up; flows are spread over them by hash.
    pub queues: u16,
    /// Whether packets pass while no process is bound to the queues (the daemon isn't running): fail-open. Queue
    /// overflow never lets packets pass either way.
    pub bypass: bool,
    /// Packets whose mark has these bits set are the daemon's own and are not queued.
    pub own_mark: u32,
    /// A queue that DNS answers (UDP from port 53) are copied to, to learn the names of addresses; `None` for none.
    /// It only observes: it always passes packets while nobody is bound to it.
    pub dns_queue: Option<u16>,
}

impl Default for Table {
    fn default() -> Self {
        Self {
            name: "snitchhiker".to_owned(),
            queue: 0,
            queues: 4,
            bypass: false,
            own_mark: 0x5_17c_000,
            dns_queue: None,
        }
    }
}

/// Sequence numbers of a batch's messages, whose acknowledgements the socket waits for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Batch {
    pub first: u32,
    pub last: u32,
    /// The sequence number to use for the next batch.
    pub next: u32,
}

/// Writes the batch that (re)creates the table: in one transaction it is created, deleted (with whatever an older
/// daemon or another tool left in it) and created again with its chain and rules, so packets see either the old
/// table or the new one, never neither.
pub fn encode_install(writer: &mut Writer, table: &Table, sequence: u32) -> Batch {
    writer.clear();
    let mut batch = Builder::start(writer, sequence);
    batch.table(NFT_MSG_NEWTABLE, NLM_F_CREATE, &table.name);
    batch.table(NFT_MSG_DELTABLE, 0, &table.name);
    batch.table(NFT_MSG_NEWTABLE, NLM_F_CREATE, &table.name);
    batch.base_chain(
        &table.name,
        "output",
        "route",
        NF_INET_LOCAL_OUT,
        NF_IP_PRI_MANGLE,
    );

    // Our own traffic (the relay connection, pushes) is never queued.
    batch.rule(&table.name, "output", |rule| {
        rule.meta(NFT_META_MARK);
        rule.bitwise(4, &table.own_mark.to_ne_bytes());
        rule.cmp(NFT_CMP_NEQ, &0_u32.to_ne_bytes());
        rule.accept();
    });
    // New TCP connections: packets with only SYN of FIN, SYN, RST and ACK set. `ct state new` would also catch
    // out-of-order packets of established connections.
    batch.rule(&table.name, "output", |rule| {
        rule.meta(NFT_META_L4PROTO);
        rule.cmp(NFT_CMP_EQ, &[IPPROTO_TCP]);
        rule.payload(NFT_PAYLOAD_TRANSPORT_HEADER, TCP_FLAGS_OFFSET, 1);
        rule.bitwise(1, &[TCP_FIN_SYN_RST_ACK]);
        rule.cmp(NFT_CMP_EQ, &[TCP_SYN]);
        rule.queue(table);
    });
    // Everything else: the first packet of a flow, and related ones (ICMP errors, FTP data and the like).
    batch.rule(&table.name, "output", |rule| {
        rule.meta(NFT_META_L4PROTO);
        rule.cmp(NFT_CMP_NEQ, &[IPPROTO_TCP]);
        rule.ct(NFT_CT_STATE);
        rule.bitwise(4, &(CT_STATE_NEW | CT_STATE_RELATED).to_ne_bytes());
        rule.cmp(NFT_CMP_NEQ, &0_u32.to_ne_bytes());
        rule.queue(table);
    });
    if let Some(dns_queue) = table.dns_queue {
        batch.base_chain(
            &table.name,
            "input",
            "filter",
            NF_INET_LOCAL_IN,
            NF_IP_PRI_MANGLE,
        );
        batch.rule(&table.name, "input", |rule| {
            rule.meta(NFT_META_L4PROTO);
            rule.cmp(NFT_CMP_EQ, &[IPPROTO_UDP]);
            rule.payload(NFT_PAYLOAD_TRANSPORT_HEADER, 0, 2);
            rule.cmp(NFT_CMP_EQ, &DNS_PORT.to_be_bytes());
            rule.queue_to(dns_queue, 1, true);
        });
    }
    batch.end()
}

/// Where the system table's rules hook in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SystemChain {
    Input,
    Forward,
    Output,
}

impl SystemChain {
    const fn name(self) -> &'static str {
        match self {
            Self::Input => "input",
            Self::Forward => "forward",
            Self::Output => "output",
        }
    }
}

/// An address prefix: 4 or 16 bytes, and how many leading bits count.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prefix {
    pub address: Vec<u8>,
    pub length: u8,
}

impl Prefix {
    fn v6(&self) -> bool {
        self.address.len() == 16
    }

    /// The prefix's mask, and the address masked by it.
    fn masked(&self) -> (Vec<u8>, Vec<u8>) {
        let mut bits = u32::from(self.length);
        let mask: Vec<u8> = self
            .address
            .iter()
            .map(|_| {
                let take = bits.min(8);
                bits -= take;
                if take == 0 { 0 } else { 0xff_u8 << (8 - take) }
            })
            .collect();
        let network = self.address.iter().zip(&mask).map(|(a, m)| a & m).collect();
        (mask, network)
    }
}

/// An interface: its name, or a prefix of names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Interface {
    pub name: String,
    pub prefix: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SystemTarget {
    Accept,
    Drop,
    Reject,
    /// Logged with this prefix; the packet goes on to the next rule.
    Log(String),
    /// To NFQUEUE `number` (and the `total - 1` after it).
    Queue {
        number: u16,
        total: u16,
        bypass: bool,
    },
}

/// One rule of the system table: every match given must hold.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemRule {
    pub chain: SystemChain,
    pub protocol: Option<u8>,
    pub source: Option<Prefix>,
    pub destination: Option<Prefix>,
    pub source_ports: Option<(u16, u16)>,
    pub destination_ports: Option<(u16, u16)>,
    pub in_interface: Option<Interface>,
    pub out_interface: Option<Interface>,
    /// Connection tracking state bits, any of which matches; 0 for any state.
    pub ct_state: u32,
    pub icmp_type: Option<u8>,
    pub target: SystemTarget,
}

/// The system firewall's table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SystemTable {
    pub name: String,
    pub input_drop: bool,
    pub forward_drop: bool,
    pub rules: Vec<SystemRule>,
}

/// Writes the batch that (re)creates the system table, in one transaction as [`encode_install`] does.
pub fn encode_system(writer: &mut Writer, table: &SystemTable, sequence: u32) -> Batch {
    writer.clear();
    let mut batch = Builder::start(writer, sequence);
    batch.table(NFT_MSG_NEWTABLE, NLM_F_CREATE, &table.name);
    batch.table(NFT_MSG_DELTABLE, 0, &table.name);
    batch.table(NFT_MSG_NEWTABLE, NLM_F_CREATE, &table.name);
    for (chain, hook, drop) in [
        (SystemChain::Input, NF_INET_LOCAL_IN, table.input_drop),
        (SystemChain::Forward, NF_INET_FORWARD, table.forward_drop),
        (SystemChain::Output, NF_INET_LOCAL_OUT, false),
    ] {
        batch.filter_chain(
            &table.name,
            chain.name(),
            hook,
            if drop { NF_DROP } else { NF_ACCEPT },
        );
    }
    for rule in &table.rules {
        batch.rule(&table.name, rule.chain.name(), |e| e.system_rule(rule));
    }
    batch.end()
}

/// Writes the batch that deletes the table (created first, so deleting it never fails because it is missing).
pub fn encode_remove(writer: &mut Writer, name: &str, sequence: u32) -> Batch {
    writer.clear();
    let mut batch = Builder::start(writer, sequence);
    batch.table(NFT_MSG_NEWTABLE, NLM_F_CREATE, name);
    batch.table(NFT_MSG_DELTABLE, 0, name);
    batch.end()
}

/// Writes a batch: the begin marker, numbered messages, the end marker.
struct Builder<'a> {
    writer: &'a mut Writer,
    first: u32,
    sequence: u32,
}

impl<'a> Builder<'a> {
    fn start(writer: &'a mut Writer, sequence: u32) -> Self {
        let begin = writer.begin(
            NFNL_MSG_BATCH_BEGIN,
            0,
            sequence,
            AF_UNSPEC,
            NFNL_SUBSYS_NFTABLES,
        );
        writer.finish(begin);
        Self {
            writer,
            first: sequence.wrapping_add(1),
            sequence,
        }
    }

    fn message(&mut self, kind: u16, flags: u16) -> crate::netlink::Open {
        self.sequence = self.sequence.wrapping_add(1);
        self.writer.begin(
            (NFNL_SUBSYS_NFTABLES << 8) | kind,
            flags | NLM_F_ACK,
            self.sequence,
            NFPROTO_INET,
            0,
        )
    }

    fn table(&mut self, kind: u16, flags: u16, name: &str) {
        let message = self.message(kind, flags);
        self.writer.string(NFTA_TABLE_NAME, name);
        self.writer.finish(message);
    }

    fn base_chain(&mut self, table: &str, name: &str, kind: &str, hook: u32, priority: i32) {
        let message = self.message(NFT_MSG_NEWCHAIN, NLM_F_CREATE);
        self.writer.string(NFTA_CHAIN_TABLE, table);
        self.writer.string(NFTA_CHAIN_NAME, name);
        let nested = self.writer.nest(NFTA_CHAIN_HOOK);
        self.writer.u32_be(NFTA_HOOK_HOOKNUM, hook);
        self.writer
            .attribute(NFTA_HOOK_PRIORITY, &priority.to_be_bytes());
        self.writer.end(nested);
        self.writer.u32_be(NFTA_CHAIN_POLICY, NF_ACCEPT);
        self.writer.string(NFTA_CHAIN_TYPE, kind);
        self.writer.finish(message);
    }

    fn filter_chain(&mut self, table: &str, name: &str, hook: u32, policy: u32) {
        let message = self.message(NFT_MSG_NEWCHAIN, NLM_F_CREATE);
        self.writer.string(NFTA_CHAIN_TABLE, table);
        self.writer.string(NFTA_CHAIN_NAME, name);
        let nested = self.writer.nest(NFTA_CHAIN_HOOK);
        self.writer.u32_be(NFTA_HOOK_HOOKNUM, hook);
        self.writer
            .attribute(NFTA_HOOK_PRIORITY, &NF_IP_PRI_FILTER.to_be_bytes());
        self.writer.end(nested);
        self.writer.u32_be(NFTA_CHAIN_POLICY, policy);
        self.writer.string(NFTA_CHAIN_TYPE, "filter");
        self.writer.finish(message);
    }

    fn rule(&mut self, table: &str, chain: &str, expressions: impl FnOnce(&mut Expressions<'_>)) {
        let message = self.message(NFT_MSG_NEWRULE, NLM_F_CREATE | NLM_F_APPEND);
        self.writer.string(NFTA_RULE_TABLE, table);
        self.writer.string(NFTA_RULE_CHAIN, chain);
        let list = self.writer.nest(NFTA_RULE_EXPRESSIONS);
        expressions(&mut Expressions {
            writer: self.writer,
        });
        self.writer.end(list);
        self.writer.finish(message);
    }

    fn end(self) -> Batch {
        let last = self.sequence;
        let end = self.writer.begin(
            NFNL_MSG_BATCH_END,
            0,
            last.wrapping_add(1),
            AF_UNSPEC,
            NFNL_SUBSYS_NFTABLES,
        );
        self.writer.finish(end);
        Batch {
            first: self.first,
            last,
            next: last.wrapping_add(2),
        }
    }
}

/// The expressions of one rule. They all work on register 1, except the verdicts.
struct Expressions<'a> {
    writer: &'a mut Writer,
}

impl Expressions<'_> {
    fn expression(&mut self, name: &str, data: impl FnOnce(&mut Writer)) {
        let element = self.writer.nest(NFTA_LIST_ELEM);
        self.writer.string(NFTA_EXPR_NAME, name);
        let nested = self.writer.nest(NFTA_EXPR_DATA);
        data(self.writer);
        self.writer.end(nested);
        self.writer.end(element);
    }

    fn meta(&mut self, key: u32) {
        self.expression("meta", |w| {
            w.u32_be(NFTA_META_KEY, key);
            w.u32_be(NFTA_META_DREG, NFT_REG_1);
        });
    }

    fn ct(&mut self, key: u32) {
        self.expression("ct", |w| {
            w.u32_be(NFTA_CT_KEY, key);
            w.u32_be(NFTA_CT_DREG, NFT_REG_1);
        });
    }

    fn payload(&mut self, base: u32, offset: u32, length: u32) {
        self.expression("payload", |w| {
            w.u32_be(NFTA_PAYLOAD_DREG, NFT_REG_1);
            w.u32_be(NFTA_PAYLOAD_BASE, base);
            w.u32_be(NFTA_PAYLOAD_OFFSET, offset);
            w.u32_be(NFTA_PAYLOAD_LEN, length);
        });
    }

    /// Register 1 = register 1 & `mask` (the mask is `length` bytes, in the register's byte order).
    fn bitwise(&mut self, length: u32, mask: &[u8]) {
        self.expression("bitwise", |w| {
            w.u32_be(NFTA_BITWISE_SREG, NFT_REG_1);
            w.u32_be(NFTA_BITWISE_DREG, NFT_REG_1);
            w.u32_be(NFTA_BITWISE_LEN, length);
            let nested = w.nest(NFTA_BITWISE_MASK);
            w.attribute(NFTA_DATA_VALUE, mask);
            w.end(nested);
            let nested = w.nest(NFTA_BITWISE_XOR);
            w.attribute(
                NFTA_DATA_VALUE,
                [0; 16].get(..mask.len()).unwrap_or_default(),
            );
            w.end(nested);
        });
    }

    fn cmp(&mut self, op: u32, value: &[u8]) {
        self.expression("cmp", |w| {
            w.u32_be(NFTA_CMP_SREG, NFT_REG_1);
            w.u32_be(NFTA_CMP_OP, op);
            let nested = w.nest(NFTA_CMP_DATA);
            w.attribute(NFTA_DATA_VALUE, value);
            w.end(nested);
        });
    }

    fn accept(&mut self) {
        self.verdict(NF_ACCEPT);
    }

    fn verdict(&mut self, code: u32) {
        self.expression("immediate", |w| {
            w.u32_be(NFTA_IMMEDIATE_DREG, NFT_REG_VERDICT);
            let data = w.nest(NFTA_IMMEDIATE_DATA);
            let verdict = w.nest(NFTA_DATA_VERDICT);
            w.u32_be(NFTA_VERDICT_CODE, code);
            w.end(verdict);
            w.end(data);
        });
    }

    /// Register 1 within the ports, inclusive.
    fn ports(&mut self, offset: u32, (low, high): (u16, u16)) {
        self.payload(NFT_PAYLOAD_TRANSPORT_HEADER, offset, 2);
        if low == high {
            self.cmp(NFT_CMP_EQ, &low.to_be_bytes());
        } else {
            self.cmp(NFT_CMP_GTE, &low.to_be_bytes());
            self.cmp(NFT_CMP_LTE, &high.to_be_bytes());
        }
    }

    fn address(&mut self, prefix: &Prefix, source: bool) {
        let (offset, length) = match (prefix.v6(), source) {
            (false, true) => (12, 4),
            (false, false) => (16, 4),
            (true, true) => (8, 16),
            (true, false) => (24, 16),
        };
        self.payload(NFT_PAYLOAD_NETWORK_HEADER, offset, length);
        let (mask, network) = prefix.masked();
        if usize::from(prefix.length) < mask.len() * 8 {
            self.bitwise(length, &mask);
        }
        self.cmp(NFT_CMP_EQ, &network);
    }

    fn interface(&mut self, key: u32, interface: &Interface) {
        self.meta(key);
        let mut name = interface.name.as_bytes().to_vec();
        if !interface.prefix {
            name.resize(IFNAMSIZ, 0);
        }
        self.cmp(NFT_CMP_EQ, &name);
    }

    fn system_rule(&mut self, rule: &SystemRule) {
        let family = rule
            .source
            .as_ref()
            .or(rule.destination.as_ref())
            .map(Prefix::v6);
        if let Some(v6) = family {
            self.meta(NFT_META_NFPROTO);
            self.cmp(NFT_CMP_EQ, &[if v6 { NFPROTO_IPV6 } else { NFPROTO_IPV4 }]);
        }
        if let Some(interface) = &rule.in_interface {
            self.interface(NFT_META_IIFNAME, interface);
        }
        if let Some(interface) = &rule.out_interface {
            self.interface(NFT_META_OIFNAME, interface);
        }
        if let Some(prefix) = &rule.source {
            self.address(prefix, true);
        }
        if let Some(prefix) = &rule.destination {
            self.address(prefix, false);
        }
        if let Some(protocol) = rule.protocol {
            self.meta(NFT_META_L4PROTO);
            self.cmp(NFT_CMP_EQ, &[protocol]);
        }
        if let Some(ports) = rule.source_ports {
            self.ports(0, ports);
        }
        if let Some(ports) = rule.destination_ports {
            self.ports(2, ports);
        }
        if let Some(icmp_type) = rule.icmp_type {
            self.payload(NFT_PAYLOAD_TRANSPORT_HEADER, 0, 1);
            self.cmp(NFT_CMP_EQ, &[icmp_type]);
        }
        if rule.ct_state != 0 {
            self.ct(NFT_CT_STATE);
            self.bitwise(4, &rule.ct_state.to_ne_bytes());
            self.cmp(NFT_CMP_NEQ, &0_u32.to_ne_bytes());
        }
        match &rule.target {
            SystemTarget::Accept => self.verdict(NF_ACCEPT),
            SystemTarget::Drop => self.verdict(NF_DROP),
            SystemTarget::Reject => {
                let tcp = rule.protocol == Some(IPPROTO_TCP);
                self.expression("reject", |w| {
                    if tcp {
                        w.u32_be(NFTA_REJECT_TYPE, NFT_REJECT_TCP_RST);
                    } else {
                        w.u32_be(NFTA_REJECT_TYPE, NFT_REJECT_ICMPX_UNREACH);
                        w.attribute(NFTA_REJECT_ICMP_CODE, &[NFT_REJECT_ICMPX_PORT_UNREACH]);
                    }
                });
            }
            SystemTarget::Log(prefix) => {
                self.expression("log", |w| w.string(NFTA_LOG_PREFIX, prefix));
            }
            SystemTarget::Queue {
                number,
                total,
                bypass,
            } => self.queue_to(*number, *total, *bypass),
        }
    }

    fn queue(&mut self, table: &Table) {
        self.queue_to(table.queue, table.queues, table.bypass);
    }

    fn queue_to(&mut self, number: u16, total: u16, bypass: bool) {
        self.expression("queue", |w| {
            w.u16_be(NFTA_QUEUE_NUM, number);
            w.u16_be(NFTA_QUEUE_TOTAL, total.max(1));
            w.u16_be(
                NFTA_QUEUE_FLAGS,
                if bypass { NFT_QUEUE_FLAG_BYPASS } else { 0 },
            );
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::netlink::{NFGENMSG_LEN, attributes, messages};

    fn kinds(writer: &Writer) -> Vec<(u16, u32)> {
        messages(writer.bytes())
            .map(|message| (message.kind, message.sequence))
            .collect()
    }

    #[test]
    fn install_replaces_the_table_in_one_batch() {
        let mut writer = Writer::new();
        let batch = encode_install(&mut writer, &Table::default(), 100);
        let nft = |kind: u16| (NFNL_SUBSYS_NFTABLES << 8) | kind;
        assert_eq!(
            kinds(&writer),
            vec![
                (NFNL_MSG_BATCH_BEGIN, 100),
                (nft(NFT_MSG_NEWTABLE), 101),
                (nft(NFT_MSG_DELTABLE), 102),
                (nft(NFT_MSG_NEWTABLE), 103),
                (nft(NFT_MSG_NEWCHAIN), 104),
                (nft(NFT_MSG_NEWRULE), 105),
                (nft(NFT_MSG_NEWRULE), 106),
                (nft(NFT_MSG_NEWRULE), 107),
                (NFNL_MSG_BATCH_END, 108),
            ]
        );
        assert_eq!(
            batch,
            Batch {
                first: 101,
                last: 107,
                next: 109
            }
        );
    }

    #[test]
    fn rules_name_their_table_and_chain() {
        let mut writer = Writer::new();
        encode_install(&mut writer, &Table::default(), 0);
        let rule = messages(writer.bytes())
            .find(|m| m.kind == (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWRULE)
            .unwrap();
        let attrs: Vec<_> = attributes(&rule.body[NFGENMSG_LEN..]).collect();
        assert_eq!(attrs[0], (NFTA_RULE_TABLE, &b"snitchhiker\0"[..]));
        assert_eq!(attrs[1], (NFTA_RULE_CHAIN, &b"output\0"[..]));
        let names: Vec<_> = attributes(attrs[2].1)
            .map(|(_, expression)| attributes(expression).next().unwrap().1)
            .collect();
        assert_eq!(
            names,
            vec![&b"meta\0"[..], b"bitwise\0", b"cmp\0", b"immediate\0"]
        );
    }

    #[test]
    fn the_system_table_has_three_chains_and_a_rule_each() {
        let mut writer = Writer::new();
        let rule = |chain, target| SystemRule {
            chain,
            protocol: Some(IPPROTO_TCP),
            source: Some(Prefix {
                address: vec![10, 1, 2, 3],
                length: 8,
            }),
            destination: None,
            source_ports: None,
            destination_ports: Some((8000, 8999)),
            in_interface: Some(Interface {
                name: "eth".to_owned(),
                prefix: true,
            }),
            out_interface: None,
            ct_state: 0,
            icmp_type: None,
            target,
        };
        let table = SystemTable {
            name: "snitchhiker_system".to_owned(),
            input_drop: true,
            forward_drop: false,
            rules: vec![
                rule(SystemChain::Input, SystemTarget::Reject),
                rule(SystemChain::Output, SystemTarget::Log("x ".to_owned())),
            ],
        };
        let batch = encode_system(&mut writer, &table, 0);
        assert_eq!(kinds(&writer).len(), 1 + 3 + 3 + 2 + 1);
        assert_eq!((batch.first, batch.last), (1, 8));
        let rule = messages(writer.bytes())
            .find(|m| m.kind == (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_NEWRULE)
            .unwrap();
        let attrs: Vec<_> = attributes(&rule.body[NFGENMSG_LEN..]).collect();
        let names: Vec<_> = attributes(attrs[2].1)
            .map(|(_, expression)| attributes(expression).next().unwrap().1)
            .collect();
        // Family, interface prefix, network, protocol, a port range, reject.
        assert_eq!(
            names,
            vec![
                &b"meta\0"[..],
                b"cmp\0",
                b"meta\0",
                b"cmp\0",
                b"payload\0",
                b"bitwise\0",
                b"cmp\0",
                b"meta\0",
                b"cmp\0",
                b"payload\0",
                b"cmp\0",
                b"cmp\0",
                b"reject\0",
            ]
        );
    }

    #[test]
    fn prefixes_mask_their_address() {
        let prefix = Prefix {
            address: vec![10, 1, 2, 3],
            length: 12,
        };
        assert_eq!(prefix.masked(), (vec![255, 240, 0, 0], vec![10, 0, 0, 0]));
    }

    #[test]
    fn remove_never_fails_on_a_missing_table() {
        let mut writer = Writer::new();
        let batch = encode_remove(&mut writer, "snitchhiker", 5);
        assert_eq!(kinds(&writer).len(), 4);
        assert_eq!((batch.first, batch.last), (6, 7));
    }
}
