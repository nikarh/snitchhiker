//! Our `nf_tables` table, created over netlink and checked with `nft` (the only place `nft` is used: to look).

use snitchhiker_netfilter::netlink::{Socket, Writer};
use snitchhiker_netfilter::nftables::{Table, encode_install, encode_remove};

use crate::util::{check, run};

fn install_table(table: &Table) -> Result<(), String> {
    let mut socket = Socket::open().map_err(|e| format!("netlink socket: {e}"))?;
    let mut writer = Writer::new();
    let batch = encode_install(&mut writer, table, 1);
    socket
        .transact(&writer, batch.first, batch.last)
        .map_err(|e| format!("installing the table: {e}"))
}

fn remove_table(name: &str) -> Result<(), String> {
    let mut socket = Socket::open().map_err(|e| format!("netlink socket: {e}"))?;
    let mut writer = Writer::new();
    let batch = encode_remove(&mut writer, name, 1);
    socket
        .transact(&writer, batch.first, batch.last)
        .map_err(|e| format!("removing the table: {e}"))
}

fn listed() -> Result<String, String> {
    run("nft", &["list", "table", "inet", "snitchhiker"])
}

pub fn install() -> Result<(), String> {
    install_table(&Table::default())?;
    let table = listed()?;
    remove_table("snitchhiker")?;
    for expected in [
        "chain output",
        "type route hook output priority mangle; policy accept;",
        "meta mark & 0x0517c000 != 0x00000000 accept",
        "tcp flags & (fin | syn | rst | ack) == syn queue to 0-3",
        "meta l4proto != tcp ct state related,new queue to 0-3",
    ] {
        check(
            table.contains(expected),
            &format!("missing `{expected}`"),
            &table,
        )?;
    }
    Ok(())
}

pub fn reinstall_replaces() -> Result<(), String> {
    install_table(&Table::default())?;
    // Something added to our table behind our back is gone after the next install.
    run("nft", &["add", "chain", "inet", "snitchhiker", "stray"])?;
    let bypass = Table {
        bypass: true,
        ..Table::default()
    };
    install_table(&bypass)?;
    let table = listed()?;
    remove_table("snitchhiker")?;
    check(!table.contains("stray"), "the stray chain survived", &table)?;
    check(
        table.contains("queue flags bypass to 0-3"),
        "the new table is not in place",
        &table,
    )
}

pub fn remove() -> Result<(), String> {
    install_table(&Table::default())?;
    remove_table("snitchhiker")?;
    remove_table("snitchhiker")?;
    let tables = run("nft", &["list", "tables"])?;
    check(
        !tables.contains("snitchhiker"),
        "the table is still there",
        &tables,
    )
}

pub fn other_tables_untouched() -> Result<(), String> {
    run("nft", &["add", "table", "inet", "someone_else"])?;
    run(
        "nft",
        &[
            "add",
            "chain",
            "inet",
            "someone_else",
            "input",
            "{ type filter hook input priority 0; }",
        ],
    )?;
    install_table(&Table::default())?;
    remove_table("snitchhiker")?;
    let theirs = run("nft", &["list", "table", "inet", "someone_else"]);
    run("nft", &["delete", "table", "inet", "someone_else"])?;
    let theirs = theirs?;
    check(
        theirs.contains("chain input"),
        "another table was changed",
        &theirs,
    )
}
