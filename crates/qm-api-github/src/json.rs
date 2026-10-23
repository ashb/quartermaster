use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use std::fmt;

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum Json {
    Null,
    Bool(bool),
    Number(serde_json::Number),
    String(String),
    Array(Vec<Json>),
    Object(Vec<(String, Json)>),
}

impl Json {
    pub(crate) fn charge(&self, remaining: &mut usize) -> bool {
        let cost = 32usize.saturating_add(match self {
            Self::String(value) => value.len(),
            _ => 0,
        });
        let Some(next) = remaining.checked_sub(cost) else {
            return false;
        };
        *remaining = next;
        match self {
            Self::Array(values) => values.iter().all(|value| value.charge(remaining)),
            Self::Object(fields) => fields.iter().all(|(key, value)| {
                let Some(next) = remaining.checked_sub(key.len()) else {
                    return false;
                };
                *remaining = next;
                value.charge(remaining)
            }),
            _ => true,
        }
    }
    pub(crate) fn object(&self) -> Option<&[(String, Self)]> {
        if let Self::Object(fields) = self {
            Some(fields)
        } else {
            None
        }
    }
    pub(crate) fn string(&self) -> Option<&str> {
        if let Self::String(value) = self {
            Some(value)
        } else {
            None
        }
    }
    pub(crate) fn unique(&self, key: &str) -> Option<&Self> {
        let mut matching = self.object()?.iter().filter(|(name, _)| name == key);
        let (_, value) = matching.next()?;
        if matching.next().is_some() {
            None
        } else {
            Some(value)
        }
    }
    pub(crate) fn duplicate_members(&self) -> bool {
        match self {
            Self::Object(fields) => {
                let mut names = std::collections::BTreeSet::new();
                fields
                    .iter()
                    .any(|(name, value)| !names.insert(name) || value.duplicate_members())
            }
            Self::Array(values) => values.iter().any(Self::duplicate_members),
            _ => false,
        }
    }
}

pub(crate) fn check_depth(bytes: &[u8], limit: usize) -> Result<(), crate::AnalysisError> {
    let mut quoted = false;
    let mut escaped = false;
    let mut depth = 0usize;
    for byte in bytes {
        if quoted {
            if escaped {
                escaped = false;
            } else if *byte == b'\\' {
                escaped = true;
            } else if *byte == b'"' {
                quoted = false;
            }
        } else {
            match byte {
                b'"' => quoted = true,
                b'{' | b'[' => {
                    depth += 1;
                    if depth > limit.min(64) {
                        return Err(crate::AnalysisError::Limit);
                    }
                }
                b'}' | b']' => depth = depth.saturating_sub(1),
                _ => {}
            }
        }
    }
    Ok(())
}

struct JsonVisitor;

impl<'de> Visitor<'de> for JsonVisitor {
    type Value = Json;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("JSON data")
    }
    fn visit_unit<E: de::Error>(self) -> Result<Json, E> {
        Ok(Json::Null)
    }
    fn visit_bool<E: de::Error>(self, value: bool) -> Result<Json, E> {
        Ok(Json::Bool(value))
    }
    fn visit_i64<E: de::Error>(self, value: i64) -> Result<Json, E> {
        Ok(Json::Number(value.into()))
    }
    fn visit_u64<E: de::Error>(self, value: u64) -> Result<Json, E> {
        Ok(Json::Number(value.into()))
    }
    fn visit_f64<E: de::Error>(self, value: f64) -> Result<Json, E> {
        serde_json::Number::from_f64(value)
            .map(Json::Number)
            .ok_or_else(|| E::custom("invalid number"))
    }
    fn visit_str<E: de::Error>(self, value: &str) -> Result<Json, E> {
        Ok(Json::String(value.into()))
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut access: A) -> Result<Json, A::Error> {
        let mut values = Vec::new();
        while let Some(value) = access.next_element()? {
            values.push(value);
        }
        Ok(Json::Array(values))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut access: A) -> Result<Json, A::Error> {
        let mut fields = Vec::new();
        while let Some(field) = access.next_entry()? {
            fields.push(field);
        }
        Ok(Json::Object(fields))
    }
}

impl<'de> Deserialize<'de> for Json {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(JsonVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escaped_duplicates_are_preserved_and_never_silently_selected() {
        let value: Json =
            serde_json::from_str(r#"{"state":"open","st\u0061te":"closed"}"#).unwrap();
        assert!(value.duplicate_members());
        assert!(value.unique("state").is_none());
        assert_eq!(value.object().unwrap().len(), 2);
    }
}
