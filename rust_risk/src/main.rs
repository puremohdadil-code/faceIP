use std::io::{self, BufRead};

fn value(line: &str, key: &str) -> String {
    let marker = format!("\"{}\":\"", key);
    line.find(&marker)
        .and_then(|start| {
            let begin = start + marker.len();
            line[begin..].find('"').map(|end| line[begin..begin + end].to_string())
        })
        .unwrap_or_default()
}

fn risk(status: &str, hostname: &str, source: &str, metadata: &str) -> (u8, &'static str) {
    if status == "new" { return (35, "device_seen_for_the_first_time"); }
    if hostname.is_empty() && source == "arp" { return (10, "hostname_not_resolved"); }
    if metadata.contains("unknown") { return (15, "identity_confidence_is_low"); }
    (0, "no_elevated_indicators")
}

fn main() {
    for line in io::stdin().lock().lines().flatten() {
        let status = value(&line, "status");
        let hostname = value(&line, "hostname");
        let source = value(&line, "source");
        let metadata = value(&line, "device_class");
        let device_id = value(&line, "device_id");
            let lua_score = value(&line, "lua_score").parse::<u8>().unwrap_or(0);
            let lua_reason = value(&line, "lua_reasons");
            let (base_score, base_reason) = risk(&status, &hostname, &source, &metadata);
            let (score, reason) = if lua_score > base_score {
                (lua_score, if lua_reason.is_empty() { base_reason } else { lua_reason.as_str() })
            } else {
                (base_score, base_reason)
            };
        println!("{{\"schema_version\":\"1.0\",\"kind\":\"assessment\",\"module\":\"rust_risk\",\"payload\":{{\"device_id\":\"{}\",\"risk\":{},\"reason\":\"{}\"}}}}", device_id, score, reason);
    }
}
