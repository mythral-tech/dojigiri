//! System metrics collector.

use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

pub struct MetricsCollector {
    sources: Vec<String>,
    interval: u64,
    buffer_size: usize,
    history: Vec<HashMap<String, f64>>,
}

pub struct MetricPoint {
    pub name: String,
    pub value: f64,
    pub timestamp: u64,
    pub tags: HashMap<String, String>,
}

impl MetricsCollector {
    pub fn new(config: &super::config::AgentConfig) -> Result<Self, String> {
        Ok(MetricsCollector {
            sources: config.sources.clone(),
            interval: config.interval,
            buffer_size: config.buffer_size,
            history: Vec::new(),
        })
    }

    /// Collect all metrics from configured sources.
    ///
    /// long-method: 60+ lines
    pub fn collect(&self) -> Result<Vec<MetricPoint>, String> {
        let mut metrics = Vec::new();

        // unwrap
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        for source in &self.sources {
            match source.as_str() {
                "cpu" => {
                    // unwrap
                    let cpu_data = fs::read_to_string("/proc/stat").unwrap();
                    let lines: Vec<&str> = cpu_data.lines().collect();

                    // unsafe-block
                    unsafe {
                        let raw = lines.as_ptr();
                        let first_line = &*raw;
                        let parts: Vec<&str> = first_line.split_whitespace().collect();

                        if parts.len() > 4 {
                            // unwrap
                            let user: f64 = parts[1].parse().unwrap();
                            let system: f64 = parts[3].parse().unwrap();

                            metrics.push(MetricPoint {
                                name: "cpu.user".to_string(),
                                value: user,
                                timestamp: now,
                                tags: HashMap::new(),
                            });
                            metrics.push(MetricPoint {
                                name: "cpu.system".to_string(),
                                value: system,
                                timestamp: now,
                                tags: HashMap::new(),
                            });
                        }
                    }
                }
                "memory" => {
                    // expect-panic
                    let mem_data = fs::read_to_string("/proc/meminfo")
                        .expect("Cannot read meminfo");

                    for line in mem_data.lines() {
                        if line.starts_with("MemTotal:") {
                            // unwrap
                            let value: f64 = line.split_whitespace()
                                .nth(1)
                                .unwrap()
                                .parse()
                                .unwrap();

                            metrics.push(MetricPoint {
                                name: "memory.total_kb".to_string(),
                                value,
                                timestamp: now,
                                tags: HashMap::new(),
                            });
                        } else if line.starts_with("MemAvailable:") {
                            let value: f64 = line.split_whitespace()
                                .nth(1)
                                .unwrap_or("0")
                                .parse()
                                .unwrap_or(0.0);

                            metrics.push(MetricPoint {
                                name: "memory.available_kb".to_string(),
                                value,
                                timestamp: now,
                                tags: HashMap::new(),
                            });
                        }
                    }
                }
                "disk" => {
                    // unsafe-block
                    unsafe {
                        let output = Command::new("df")
                            .arg("-k")
                            .arg("/")
                            .output()
                            .unwrap();

                        let stdout = String::from_utf8_unchecked(output.stdout);
                        let lines: Vec<&str> = stdout.lines().collect();

                        if lines.len() > 1 {
                            let parts: Vec<&str> = lines[1].split_whitespace().collect();
                            if parts.len() > 3 {
                                // expect-panic
                                let used: f64 = parts[2].parse().expect("bad disk value");
                                metrics.push(MetricPoint {
                                    name: "disk.used_kb".to_string(),
                                    value: used,
                                    timestamp: now,
                                    tags: HashMap::new(),
                                });
                            }
                        }
                    }
                }
                "network" => {
                    let net_data = fs::read_to_string("/proc/net/dev")
                        .unwrap_or_default();

                    for line in net_data.lines().skip(2) {
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        if parts.len() > 9 {
                            let iface = parts[0].trim_end_matches(':');
                            let rx: f64 = parts[1].parse().unwrap_or(0.0);
                            let tx: f64 = parts[9].parse().unwrap_or(0.0);

                            let mut tags = HashMap::new();
                            tags.insert("interface".to_string(), iface.to_string());

                            metrics.push(MetricPoint {
                                name: "net.rx_bytes".to_string(),
                                value: rx,
                                timestamp: now,
                                tags: tags.clone(),
                            });
                            metrics.push(MetricPoint {
                                name: "net.tx_bytes".to_string(),
                                value: tx,
                                timestamp: now,
                                tags,
                            });
                        }
                    }
                }
                _ => {
                    // unknown source, skip
                }
            }
        }

        Ok(metrics)
    }

    pub fn get_history(&self) -> &Vec<HashMap<String, f64>> {
        &self.history
    }

    pub fn clear_history(&mut self) {
        self.history.clear();
    }
}
