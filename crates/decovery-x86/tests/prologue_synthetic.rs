//! Prologue search with placeholder bytes and a resolved call target; 386-prefixed instructions in 16-bit code.

use decovery_core::address::Address;
use decovery_x86::{PatternByte, ProloguePattern, decode, find_prologues};

fn seg(off: u16) -> Address {
    Address::Seg { seg: 0, off }
}

fn aztec() -> ProloguePattern {
    ProloguePattern::parse("B8 ?? ?? E8 ?? ??", Some("$csav")).expect("pattern")
}

/// `mov ax,-N; call rel` at `at` calling `target` (all offsets in segment 0).
fn frame(code: &mut Vec<u8>, at: u16, n: u16, target: u16) {
    let disp = target.wrapping_sub(at + 6);
    code.extend([0xB8]);
    code.extend(n.wrapping_neg().to_le_bytes());
    code.extend([0xE8]);
    code.extend(disp.to_le_bytes());
}

fn csav_at(target: u16) -> impl Fn(Address) -> Option<String> {
    move |a| (a == seg(target)).then(|| "$csav".to_string())
}

#[test]
fn pattern_text_parses() {
    let p = aztec();
    assert_eq!(p.bytes.len(), 6);
    assert_eq!(p.bytes[0], PatternByte::Exact(0xB8));
    assert_eq!(p.bytes[1], PatternByte::Any);
    assert_eq!(p.call_target.as_deref(), Some("$csav"));
    assert!(ProloguePattern::parse("B8 ?", None).is_err());
    assert!(ProloguePattern::parse("B8 GG", None).is_err());
    assert!(ProloguePattern::parse("", None).is_err());
    // with a call target the last two bytes must be placeholders
    assert!(ProloguePattern::parse("B8 ?? ?? E8 00 00", Some("$csav")).is_err());
}

#[test]
fn placeholder_bytes_match_any() {
    let mut code = Vec::new();
    frame(&mut code, 0, 4, 0x0100);
    code.extend([0xC3, 0x90]);
    let at = code.len() as u16;
    frame(&mut code, at, 0x20, 0x0100);
    code.push(0xC3);
    let found = find_prologues(&code, seg(0), &aztec(), &csav_at(0x0100));
    assert_eq!(found, vec![seg(0), seg(at)]);
}

#[test]
fn call_target_must_resolve() {
    let mut code = Vec::new();
    frame(&mut code, 0, 4, 0x0100);
    let at = code.len() as u16;
    frame(&mut code, at, 4, 0x0200); // calls something else
    let found = find_prologues(&code, seg(0), &aztec(), &csav_at(0x0100));
    assert_eq!(found, vec![seg(0)]);
    // nothing resolves: no match at all
    assert!(find_prologues(&code, seg(0), &aztec(), &|_| None).is_empty());
}

#[test]
fn call_target_in_an_overlay_uses_the_processor_address() {
    let name = decovery_core::address::OverlayName::new("VPCMK").expect("name");
    let base = Address::Ovl {
        overlay: name,
        seg: 0x1234,
        off: 0x8000,
    };
    let mut code = Vec::new();
    // call from ovl:VPCMK:1234:8000 to 1234:0100 (wraps below the overlay)
    let disp = 0x0100u16.wrapping_sub(0x8006);
    code.extend([0xB8, 0xFC, 0xFF, 0xE8]);
    code.extend(disp.to_le_bytes());
    let resolve = |a: Address| match a {
        Address::Ovl {
            seg: 0x1234,
            off: 0x0100,
            ..
        } => Some("$csav".to_string()),
        _ => None,
    };
    assert_eq!(find_prologues(&code, base, &aztec(), &resolve), vec![base]);
}

#[test]
fn no_match_in_data() {
    // data that happens to contain B8 .. .. E8 .. .. without a call to the helper, and a truncated tail
    let code = [
        0x00, 0xB8, 0x12, 0x34, 0xE8, 0x00, 0x00, 0x41, 0x42, 0xB8, 0x00, 0x00, 0xE8, 0x01,
    ];
    assert!(find_prologues(&code, seg(0), &aztec(), &csav_at(0x0100)).is_empty());
    // a pattern without call target matches the bytes, overlapping matches count once each
    let plain = ProloguePattern::parse("B8 ?? ?? E8", None).expect("pattern");
    assert_eq!(
        find_prologues(&code, seg(0), &plain, &|_| None),
        vec![seg(1), seg(9)]
    );
    // a base too close to the end of the segment never panics
    let _ = find_prologues(&code, seg(0xFFFE), &plain, &|_| None);
    assert!(find_prologues(&[], seg(0), &plain, &|_| None).is_empty());
}

#[test]
fn prefixed_386_instructions_in_16_bit_code() {
    let code = [
        0x66, 0xB8, 0x78, 0x56, 0x34, 0x12, // mov eax, 12345678h
        0x66, 0x50, // push eax
        0x67, 0x8B, 0x00, // mov ax, [eax]
        0x66, 0x67, 0x89, 0x44, 0x24, 0x08, // mov [esp+8], eax
        0x66, 0x0F, 0xB6, 0xC0, // movzx eax, al
        0x66, 0x68, 0x01, 0x00, 0x00, 0x00, // push dword 1
        0xB8, 0x01, 0x00, // mov ax, 1
        0xC3,
    ];
    let ins = decode(&code, 16, 0);
    let lens: Vec<u8> = ins.iter().map(|i| i.len).collect();
    assert_eq!(lens, [6, 2, 3, 6, 4, 6, 3, 1]);
    assert_eq!(
        ins.iter().map(|i| u32::from(i.len)).sum::<u32>(),
        code.len() as u32
    );
    assert!(ins[0].text.contains("eax"), "{}", ins[0].text);
    assert!(ins[1].text.contains("eax"), "{}", ins[1].text);
    assert!(ins[2].text.contains("[eax]"), "{}", ins[2].text);
    // the 32-bit form is not the same instruction as the 16-bit one
    let shapes: Vec<String> =
        decovery_x86::decode_detailed(&code, 16, 0, &decovery_x86::DecodeOptions::default())
            .into_iter()
            .map(|d| d.shape)
            .collect();
    assert_ne!(shapes[0], shapes[6]);
}
