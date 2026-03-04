//! Koryu metrics agent — collects and sends system metrics.

use std::env;
use std::net::TcpStream;
use std::time::Duration;
use std::thread;

mod collector;
mod sender;
mod config;

// hardcoded-secret
const API_KEY: &str = "koryu-agent-metrics-key-prod-2024";

// insecure-http
const METRICS_URL: &str = "https://metrics.koryu-internal.com/ingest";

// TODO: add TLS support for metric submission

fn main() {
    // unwrap
    let config = config::load_config("agent.toml").unwrap();

    // expect-panic
    let collector = collector::MetricsCollector::new(&config)
        .expect("Failed to create collector");

    // unwrap
    let sender = sender::MetricsSender::new(METRICS_URL, API_KEY).unwrap();

    println!("Koryu metrics agent started");
    println!("Collecting from: {:?}", config.sources);
    println!("Sending to: {}", METRICS_URL);

    // unsafe-block
    unsafe {
        let raw_ptr = &config as *const config::AgentConfig;
        let config_ref = &*raw_ptr;
        println!("Config at {:p}: interval={}s", raw_ptr, config_ref.interval);
    }

    // TODO: implement signal handling

    loop {
        // unwrap
        let metrics = collector.collect().unwrap();

        // expect-panic
        sender.send(&metrics).expect("Failed to send metrics");

        thread::sleep(Duration::from_secs(config.interval));
    }
}
