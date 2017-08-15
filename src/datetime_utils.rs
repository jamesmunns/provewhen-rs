use chrono::NaiveTime;
use chrono::prelude::*;
use chrono::DateTime;
use errors::*;
use chrono::Duration;

use std::cmp::{Ord, Ordering};
use serde::ser::{Serialize, Serializer};
use serde::de::{self, Deserialize, Deserializer, Unexpected, Visitor};
use std::fmt;

#[derive(Debug, Clone, Eq)]
pub struct ProveWhenTime {
    inner: DateTime<Utc>,
    rendered: String,
}

impl Serialize for ProveWhenTime {
    fn serialize<S>(&self, serializer: S) -> ::std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for ProveWhenTime {
    fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct TimeVisitor {};

        impl<'de> Visitor<'de> for TimeVisitor {
            type Value = ProveWhenTime;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                write!(formatter, "a valid rfc3339 string")
            }

            fn visit_str<E>(self, s: &str) -> ::std::result::Result<Self::Value, E>
            where
                E: de::Error,
            {
                match ProveWhenTime::from_str(s) {
                    Ok(time) => Ok(time),
                    _ => Err(de::Error::invalid_value(Unexpected::Str(s), &self)),
                }
            }
        }

        deserializer.deserialize_str(TimeVisitor {})
    }
}

use rocket::request::FromParam;
use rocket::http::RawStr;

impl<'r> FromParam<'r> for ProveWhenTime {
    type Error = &'r RawStr;

    fn from_param(param: &'r RawStr) -> ::std::result::Result<Self, Self::Error> {
        ProveWhenTime::from_str(&param.html_escape()).map_err(|_| param)
    }
}

impl Ord for ProveWhenTime {
    fn cmp(&self, other: &Self) -> Ordering {
        self.inner.cmp(&other.inner)
    }
}

impl PartialOrd for ProveWhenTime {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for ProveWhenTime {
    fn eq(&self, other: &Self) -> bool {
        self.inner == other.inner
    }
}

impl ProveWhenTime {
    pub fn now() -> Self {
        let time = Utc::now();
        let rendered = time.to_rfc3339();

        Self {
            inner: time,
            rendered: rendered,
        }
    }

    pub fn from_str(input: &str) -> Result<Self> {
        let time = DateTime::parse_from_rfc3339(input)
            .chain_err(|| "Failed to parse time")?
            .with_timezone(&Utc);

        let rendered = time.to_rfc3339();

        Ok(Self {
            inner: time,
            rendered: rendered,
        })
    }

    pub fn as_str(&self) -> &str {
        &self.rendered
    }

    pub fn inner(&self) -> &DateTime<Utc> {
        &self.inner
    }

    pub fn floored(&self) -> Self {
        // NOTE: Should match DateTimeRange::increment()
        let time = self.inner
            .date()
            .and_time(NaiveTime::from_hms(
                self.inner.hour(),
                (self.inner.minute() / 5) * 5,
                0,
            ))
            .unwrap();

        let rendered = time.to_rfc3339();

        Self {
            inner: time,
            rendered: rendered,
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

    #[allow(dead_code)]
    pub fn from_strs(start: &str, end: &str) -> Result<Self> {
        Ok(Self::new(
            &ProveWhenTime::from_str(start)?,
            &ProveWhenTime::from_str(end)?,
        ))
    }

    fn increment(&mut self) {
        // NOTE: Should match floored
        self.current.inner = self.current.inner + Duration::minutes(5);
        self.current.rendered = self.current.inner.to_rfc3339();
    }
}

// TODO: https://medium.com/@jordan_98525/reference-iterators-in-rust-5603a51b5192
impl Iterator for DateTimeRange {
    type Item = ProveWhenTime;

    fn next(&mut self) -> Option<Self::Item> {
        if self.current.inner < self.end.inner {
            self.increment();
            Some(self.current.clone())
        } else {
            None
        }
    }
}
