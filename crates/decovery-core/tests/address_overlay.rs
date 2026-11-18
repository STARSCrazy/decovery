//! Overlay addresses (ADR 0011).

use decovery_core::{Address, AddressError, OverlayName, address_key};

fn ovl(name: &str, seg: u16, off: u16) -> Address {
    Address::Ovl {
        overlay: OverlayName::new(name).unwrap(),
        seg,
        off,
    }
}

#[test]
fn ovl_address_round_trips() {
    let a: Address = "ovl:VINIT:0000:505E".parse().unwrap();
    assert_eq!(a, ovl("VINIT", 0, 0x505E));
    assert_eq!(a.to_string(), "ovl:VINIT:0000:505E");
    // lower case name and hex normalise to the canonical form
    let b: Address = "ovl:vinit:0ff6:909c".parse().unwrap();
    assert_eq!(b.to_string(), "ovl:VINIT:0FF6:909C");
    let json = serde_json::to_string(&a).unwrap();
    assert_eq!(json, "\"ovl:VINIT:0000:505E\"");
    assert_eq!(serde_json::from_str::<Address>(&json).unwrap(), a);
    assert_eq!(a.offset_by(2).unwrap(), ovl("VINIT", 0, 0x5060));
    assert_eq!(
        ovl("A", 0, 0xFFFF).offset_by(1),
        Err(AddressError::Overflow)
    );
}

#[test]
fn ovl_has_no_linear_address() {
    assert_eq!(ovl("VBASE", 0, 0x505E).linear(), None);
}

#[test]
fn overlay_name_rules() {
    assert_eq!(OverlayName::new("vpcvw").unwrap().as_str(), "VPCVW");
    assert_eq!(OverlayName::new("A_1").unwrap().as_str(), "A_1");
    assert_eq!(
        OverlayName::new("ABCDEFGHIJKLMNOP").unwrap().as_str(),
        "ABCDEFGHIJKLMNOP"
    );
    for bad in ["", "ABCDEFGHIJKLMNOPQ", "A-B", "A:B", "Ä", "A B"] {
        assert!(OverlayName::new(bad).is_err(), "{bad:?} should be rejected");
    }
    for bad in [
        "ovl:",
        "ovl:VINIT",
        "ovl:VINIT:0000",
        "ovl::0000:0000",
        "ovl:VINIT:00000:0000",
        "ovl:VINIT:00000000",
        "ovl:A-B:0000:0000",
    ] {
        assert!(bad.parse::<Address>().is_err(), "{bad} should be rejected");
    }
}

#[test]
fn address_key_of_ovl() {
    assert_eq!(address_key(ovl("VINIT", 0, 0x505E)), "ovl_VINIT_0000_505E");
}

#[test]
fn ovl_sorts_after_other_kinds_by_name() {
    let mut v = [
        ovl("B", 0, 1),
        ovl("A", 0, 2),
        Address::Seg { seg: 0, off: 0 },
        ovl("A", 0, 1),
    ];
    v.sort();
    assert_eq!(
        v.map(|a| a.to_string()),
        [
            "seg:0000:0000",
            "ovl:A:0000:0001",
            "ovl:A:0000:0002",
            "ovl:B:0000:0001"
        ]
    );
}
