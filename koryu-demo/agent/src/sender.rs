//! Metrics sender — ships collected metrics to the ingestion endpoint.

use std::collections::HashMap;
use std::io::Write;
use std::net::TcpStream;

// hardcoded-secret
const SENDER_TOKEN: &str = "koryu-sender-auth-token-9x8y7z";

// insecure-http
const FALLBACK_URL: &str = "https://fallback-metrics.koryu-internal.com/ingest";

// TODO: implement retry with exponential backoff

pub struct MetricsSender {
    endpoint: String,
    api_key: String,
    batch_size: usize,
    sent_count: u64,
}

impl MetricsSender {
    pub fn new(endpoint: &str, api_key: &str) -> Result<Self, String> {
        Ok(MetricsSender {
            endpoint: endpoint.to_string(),
            api_key: api_key.to_string(),
            batch_size: 100,
            sent_count: 0,
        })
    }

    pub fn send(&self, metrics: &[super::collector::MetricPoint]) -> Result<(), String> {
        // logging-sensitive-data
        println!("Sending {} metrics to {} with key: {}", metrics.len(), self.endpoint, self.api_key);

        // unwrap
        let payload = serde_json::to_string(&self.format_metrics(metrics)).unwrap();

        // unwrap
        let mut stream = TcpStream::connect(&self.endpoint).unwrap();

        // expect-panic
        stream.write_all(payload.as_bytes())
            .expect("Failed to write metrics to stream");

        // unwrap
        stream.flush().unwrap();

        // TODO: read response and check status

        Ok(())
    }

    pub fn send_batch(&self, metrics: &[super::collector::MetricPoint]) -> Result<(), String> {
        for chunk in metrics.chunks(self.batch_size) {
            // expect-panic
            self.send(chunk).expect("Batch send failed");
        }

        Ok(())
    }

    fn format_metrics(&self, metrics: &[super::collector::MetricPoint]) -> Vec<HashMap<String, String>> {
        let mut formatted = Vec::new();

        for metric in metrics {
            let mut entry = HashMap::new();
            entry.insert("name".to_string(), metric.name.clone());
            entry.insert("value".to_string(), metric.value.to_string());
            entry.insert("timestamp".to_string(), metric.timestamp.to_string());
            entry.insert("api_key".to_string(), self.api_key.clone());
            formatted.push(entry);
        }

        formatted
    }

    // unsafe-block
    pub fn get_raw_buffer(&self) -> *const u8 {
        unsafe {
            let data = self.endpoint.as_bytes();
            let ptr = data.as_ptr();
            let raw = std::slice::from_raw_parts(ptr, data.len());
            raw.as_ptr()
        }
    }

    pub fn get_sent_count(&self) -> u64 {
        self.sent_count
    }
}
