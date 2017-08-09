use chrono::NaiveTime;
use chrono::prelude::*;
use chrono::DateTime;
use errors::*;
use chrono::Duration;

#[derive(PartialEq, Clone)]
pub struct ProveWhenTime {
    inner: DateTime<Utc>,
}

impl ProveWhenTime {
    pub fn now() -> Self {
        Self { inner: Utc::now() }
    }

    pub fn from_str(input: &str) -> Result<Self> {
        Ok(Self {
            inner: DateTime::parse_from_rfc3339(input)
                .chain_err(|| "Failed to parse time")?
                .with_timezone(&Utc),
        })
    }

    pub fn to_string(&self) -> String {
        self.inner.to_rfc3339()
    }

    pub fn floored(&self) -> Self {
        Self {
            inner: self.inner
                .date()
                .and_time(NaiveTime::from_hms(self.inner.hour(), 0, 0))
                .unwrap(),
        }
    }
}

pub struct DateTimeRange {
    current: ProveWhenTime,
    end: ProveWhenTime,
}

impl DateTimeRange {
    pub fn new(start: &ProveWhenTime, end: &ProveWhenTime) -> Self {
        Self {
            current: start.floored(),
            end: end.floored(),
        }
    }

    pub fn from_strs(start: &str, end: &str) -> Result<Self> {
        Ok(Self::new(
            &ProveWhenTime::from_str(start)?,
            &ProveWhenTime::from_str(end)?,
        ))
    }

    fn increment_hour(&mut self) {
        self.current.inner = self.current.inner + Duration::hours(1);
    }
}

// TODO: https://medium.com/@jordan_98525/reference-iterators-in-rust-5603a51b5192
impl Iterator for DateTimeRange {
    type Item = ProveWhenTime;

    fn next(&mut self) -> Option<Self::Item> {
        if self.current.inner < self.end.inner {
            self.increment_hour();
            Some(self.current.clone())
        } else {
            None
        }
    }
}
