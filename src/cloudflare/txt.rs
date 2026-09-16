use std::fmt::Write;

pub(super) fn encode(value: &str) -> String {
    let mut result = String::from("\"");
    for byte in value.bytes() {
        match byte {
            b'"' | b'\\' => {
                result.push('\\');
                result.push(char::from(byte));
            }
            0x20..=0x7e => result.push(char::from(byte)),
            _ => write!(&mut result, "\\{byte:03}").expect("write to string"),
        }
    }
    result.push('"');
    result
}

pub(super) fn decode(value: &str) -> Option<String> {
    if !value.is_ascii() {
        return None;
    }
    if !value.starts_with('"') {
        return (value.len() <= 255 && !value.contains(['"', '\\'])).then(|| value.to_string());
    }
    let value = value.strip_prefix('"')?.strip_suffix('"')?;
    let mut bytes = value.bytes();
    let mut result = Vec::new();
    while let Some(byte) = bytes.next() {
        match byte {
            b'"' => return None,
            b'\\' => {
                let escaped = bytes.next()?;
                if escaped.is_ascii_digit() {
                    let second = bytes.next()?;
                    let third = bytes.next()?;
                    if !second.is_ascii_digit() || !third.is_ascii_digit() {
                        return None;
                    }
                    let value = u16::from(escaped - b'0') * 100
                        + u16::from(second - b'0') * 10
                        + u16::from(third - b'0');
                    if value > 127 {
                        return None;
                    }
                    result.push(value as u8);
                } else {
                    result.push(escaped);
                }
            }
            _ => result.push(byte),
        }
    }
    if result.len() > 255 {
        return None;
    }
    String::from_utf8(result).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ascii_round_trip() {
        let value: String = (0..=127).map(char::from).collect();
        assert_eq!(decode(&encode(&value)), Some(value));
        assert_eq!(encode("Value-A"), "\"Value-A\"");
        assert_eq!(decode("\" spaced VALUE \""), Some(" spaced VALUE ".into()));
        assert_eq!(decode("Value-A"), Some("Value-A".into()));
        assert_eq!(decode("\"\""), Some(String::new()));
        assert_eq!(decode("\"\\065\""), Some("A".into()));
    }

    #[test]
    fn unsupported_representations_do_not_match() {
        for value in ["\"a\" \"b\"", "\"a", "a\"", "\"\\999\"", "\"\\12\"", "é"] {
            assert_eq!(decode(value), None, "{value}");
        }
        assert_eq!(decode(&"a".repeat(256)), None);
    }
}
