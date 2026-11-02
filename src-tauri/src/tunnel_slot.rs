//! Decide which privileged tunnel a helper connection is still allowed to tear down.
//!
//! A newer connection replaces the active tunnel before the previous connection
//! observes EOF. The previous connection must not remove the replacement.

pub fn take_if<T>(slot: &mut Option<T>, pred: impl FnOnce(&T) -> bool) -> Option<T> {
    match slot.as_ref() {
        Some(value) if pred(value) => slot.take(),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_replaced_tunnel_is_left_in_place() {
        let mut active = Some((1u64, "old"));
        assert!(take_if(&mut active, |tunnel| tunnel.0 == 1).is_some());
        active = Some((2, "new"));
        assert!(take_if(&mut active, |tunnel| tunnel.0 == 1).is_none());
        assert_eq!(active.map(|tunnel| tunnel.1), Some("new"));
        assert_eq!(
            take_if(&mut active, |tunnel| tunnel.0 == 2).unwrap().1,
            "new"
        );
        assert!(active.is_none());
    }
}
