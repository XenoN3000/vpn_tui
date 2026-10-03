use std::fs;
use std::time::Instant;

#[derive(Debug, Clone, PartialEq, Default)]
pub struct NetStats {
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_bytes_per_sec: f64,
    pub tx_bytes_per_sec: f64,
}

impl NetStats {
    pub fn format_rate(bytes_per_sec: f64) -> String {
        if bytes_per_sec >= 1_048_576.0 {
            format!("{:.1} MB/s", bytes_per_sec / 1_048_576.0)
        } else if bytes_per_sec >= 1024.0 {
            format!("{:.1} KB/s", bytes_per_sec / 1024.0)
        } else {
            format!("{:.0} B/s", bytes_per_sec)
        }
    }

    pub fn display_speeds(&self) -> (String, String) {
        (
            Self::format_rate(self.rx_bytes_per_sec),
            Self::format_rate(self.tx_bytes_per_sec),
        )
    }
}

pub struct NetMonitor {
    last_sample: Option<(Instant, u64, u64)>,
}

impl NetMonitor {
    pub fn new() -> Self {
        Self { last_sample: None }
    }

    pub fn parse_line(line: &str, iface: &str) -> Option<(u64, u64)> {
        let trimmed = line.trim();
        let (name_part, stats_part) = trimmed.split_once(':')?;
        if name_part.trim() != iface {
            return None;
        }

        let fields: Vec<&str> = stats_part.split_whitespace().collect();
        // fields: [rx_bytes, rx_packets, rx_errs, rx_drop, ..., tx_bytes, tx_packets, ...]
        if fields.len() >= 9 {
            let rx = fields[0].parse::<u64>().ok()?;
            let tx = fields[8].parse::<u64>().ok()?;
            Some((rx, tx))
        } else {
            None
        }
    }

    pub fn parse_content(content: &str, iface: &str) -> Option<(u64, u64)> {
        for line in content.lines() {
            if let Some(stats) = Self::parse_line(line, iface) {
                return Some(stats);
            }
        }
        None
    }

    pub fn update_from_content(
        &mut self,
        content: &str,
        iface: &str,
        now: Instant,
    ) -> Option<NetStats> {
        let (rx, tx) = Self::parse_content(content, iface)?;

        let (rx_rate, tx_rate) = if let Some((last_time, last_rx, last_tx)) = self.last_sample {
            let duration = now.duration_since(last_time).as_secs_f64();
            if duration > 0.0 {
                let rx_delta = rx.saturating_sub(last_rx) as f64;
                let tx_delta = tx.saturating_sub(last_tx) as f64;
                (rx_delta / duration, tx_delta / duration)
            } else {
                (0.0, 0.0)
            }
        } else {
            (0.0, 0.0)
        };

        self.last_sample = Some((now, rx, tx));

        Some(NetStats {
            rx_bytes: rx,
            tx_bytes: tx,
            rx_bytes_per_sec: rx_rate,
            tx_bytes_per_sec: tx_rate,
        })
    }

    pub fn read_interface(&mut self, iface: &str) -> Option<NetStats> {
        let content = fs::read_to_string("/proc/net/dev").ok()?;
        self.update_from_content(&content, iface, Instant::now())
    }
}

impl Default for NetMonitor {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    const SAMPLE_PROC_DEV: &str = r#"Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo: 12345678      10    0    0    0     0          0         0 12345678      10    0    0    0     0       0          0
  tun0: 20480000     200    0    0    0     0          0         0 10240000     100    0    0    0     0       0          0
"#;

    #[test]
    fn test_parse_proc_dev_tun0() {
        let parsed = NetMonitor::parse_content(SAMPLE_PROC_DEV, "tun0");
        assert_eq!(parsed, Some((20480000, 10240000)));

        let missing = NetMonitor::parse_content(SAMPLE_PROC_DEV, "tun9");
        assert_eq!(missing, None);
    }

    #[test]
    fn test_rate_calculation() {
        let mut monitor = NetMonitor::new();
        let t0 = Instant::now();

        // Sample 1
        let s1 = monitor
            .update_from_content(SAMPLE_PROC_DEV, "tun0", t0)
            .unwrap();
        assert_eq!(s1.rx_bytes, 20480000);
        assert_eq!(s1.rx_bytes_per_sec, 0.0);

        // Sample 2 (1 second later, 1 MB rx, 500 KB tx)
        let sample2 = r#"Inter-|   Receive
  tun0: 21528576     210    0    0    0     0          0         0 10752000     110    0    0    0     0       0          0
"#;
        let t1 = t0 + Duration::from_secs(1);
        let s2 = monitor.update_from_content(sample2, "tun0", t1).unwrap();
        assert_eq!(s2.rx_bytes_per_sec, 1048576.0); // exactly 1 MB/s
        assert_eq!(s2.tx_bytes_per_sec, 512000.0);

        let (rx_fmt, tx_fmt) = s2.display_speeds();
        assert_eq!(rx_fmt, "1.0 MB/s");
        assert_eq!(tx_fmt, "500.0 KB/s");
    }
}
