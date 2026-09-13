use std::io::{self, BufRead};

fn risk(status: &str, hostname: &str, source: &str) -> (u8, &'static str) {
    if status == "new" { return (35, "device_seen_for_the_first_time"); }
    if hostname.is_empty() && source == "arp" { return (10, "hostname_not_resolved"); }
    (0, "no_elevated_indicators")
}

fn main() {
    for line in io::stdin().lock().lines().flatten() {
        let fields: Vec<&str> = line.split('\t').collect();
        if fields.len() < 3 { continue; }
        let (score, reason) = risk(fields[0], fields[1], fields[2]);
        println!("{{\"schema_version\":\"1.0\",\"kind\":\"assessment\",\"module\":\"rust_risk\",\"payload\":{{\"risk\":{},\"reason\":\"{}\"}}}}", score, reason);
    }
}
