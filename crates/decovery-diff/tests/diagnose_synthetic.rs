//! Diagnosis rules, deviation kinds and the code stage on hand-assembled 16- and 32-bit functions.

use decovery_core::{Address, ArchMode, ExecutableFormat, Permissions, Program, Region};
use decovery_diff::{
    CompareOptions, Decoration, DeviationKind, Finding, ModuleOptions, NameAt, Pair, PairKind,
    Placement, Stage, SymbolView, classify_code, classify_deviation, compare_module, diagnose,
    instruction_pairs, pairs_text,
};
use decovery_objects::{ObjSymbol, ObjectModule, Section, SectionKind, functions};

struct NoSymbols;

impl SymbolView for NoSymbols {
    fn name_at(&self, _at: Address) -> Option<NameAt> {
        None
    }

    fn address_of(&self, _name: &str) -> Option<Address> {
        None
    }
}

const AT16: Address = Address::Seg { seg: 0, off: 0x100 };
const AT32: Address = Address::Flat(0x10000);

fn program(bits: u8, original: &[u8]) -> Program {
    let (start, at, mode, format) = if bits == 16 {
        (
            Address::Seg { seg: 0, off: 0 },
            0x100usize,
            ArchMode::X86Real16,
            ExecutableFormat::Mz,
        )
    } else {
        (
            Address::Flat(0x10000),
            0,
            ArchMode::X86Flat32,
            ExecutableFormat::Le,
        )
    };
    let mut data = vec![0xCC; 0x400];
    data[at..at + original.len()].copy_from_slice(original);
    let region = Region::new(
        "code",
        start,
        0x400,
        data,
        Permissions {
            read: true,
            write: false,
            execute: true,
        },
        mode,
    );
    Program::new(format, vec![region], vec![], vec![])
}

/// The aligned pairs of `rebuild` against `original` (both complete functions).
fn pairs(bits: u8, rebuild: &[u8], original: &[u8]) -> Vec<Pair> {
    let m = ObjectModule::new(
        "t.c",
        vec![Section::new(
            "_TEXT",
            "CODE",
            SectionKind::Code,
            bits,
            rebuild.to_vec(),
            vec![],
        )],
        vec![ObjSymbol::new("_f", 0, 0, true)],
    );
    let fs = functions(&m);
    let f = fs.iter().find(|f| f.name == "_f").unwrap();
    let at = if bits == 16 { AT16 } else { AT32 };
    instruction_pairs(
        f,
        at,
        &program(bits, original),
        &NoSymbols,
        &Decoration::new("_{name}", "_{name}"),
        &CompareOptions::new(false, Some(original.len() as u32)),
    )
}

fn findings(bits: u8, rebuild: &[u8], original: &[u8], family: &str) -> Vec<Finding> {
    diagnose(&pairs(bits, rebuild, original), bits, family)
}

fn rules(findings: &[Finding]) -> Vec<&str> {
    findings.iter().map(|f| f.rule.as_str()).collect()
}

fn find<'a>(findings: &'a [Finding], rule: &str) -> &'a Finding {
    findings
        .iter()
        .find(|f| f.rule == rule)
        .unwrap_or_else(|| panic!("no {rule} in {:?}", rules(findings)))
}

// mov ax,[bp-2]; mov dx,[bp-4]; ret  against  mov ax,[bp-4]; mov dx,[bp-2]; ret
const SWAPPED_REBUILD: &[u8] = &[0x8B, 0x46, 0xFE, 0x8B, 0x56, 0xFC, 0xC3];
const SWAPPED_ORIGINAL: &[u8] = &[0x8B, 0x46, 0xFC, 0x8B, 0x56, 0xFE, 0xC3];

#[test]
fn pairs_follow_the_alignment() {
    let p = pairs(16, SWAPPED_REBUILD, SWAPPED_ORIGINAL);
    let kinds: Vec<PairKind> = p.iter().map(|p| p.kind).collect();
    assert_eq!(
        kinds,
        [PairKind::Different, PairKind::Different, PairKind::Equal]
    );
    assert_eq!(p[0].rebuild.as_ref().unwrap().offset, 0);
    assert_eq!(p[1].original.as_ref().unwrap().offset, 3);
}

#[test]
fn local_order_detects_swapped_slots() {
    let f = findings(16, SWAPPED_REBUILD, SWAPPED_ORIGINAL, "turbo-c");
    assert_eq!(rules(&f), ["local-order"]);
    let local = find(&f, "local-order");
    assert!(local.text.contains("[bp-2]→[bp-4]"), "{}", local.text);
    assert!(local.text.contains("[bp-4]→[bp-2]"), "{}", local.text);
    assert_eq!(
        local.suggestion,
        "change the declaration order of the local variables"
    );
}

#[test]
fn no_findings_when_identical() {
    assert!(findings(16, SWAPPED_REBUILD, SWAPPED_REBUILD, "turbo-c").is_empty());
    assert!(classify_deviation(&pairs(16, SWAPPED_REBUILD, SWAPPED_REBUILD)).is_none());
}

// mov ax,[1234h]; push word ptr [1234h]; ret  against  mov ax,[1234h]; push ax; ret
const Z_REBUILD: &[u8] = &[0xA1, 0x34, 0x12, 0xFF, 0x36, 0x34, 0x12, 0xC3];
const Z_ORIGINAL: &[u8] = &[0xA1, 0x34, 0x12, 0x50, 0xC3];

#[test]
fn turbo_c_z_only_for_turbo_c() {
    let f = findings(16, Z_REBUILD, Z_ORIGINAL, "turbo-c");
    let z = find(&f, "turbo-c-z");
    assert!(
        z.text.starts_with("the original uses a register"),
        "{}",
        z.text
    );
    assert!(z.suggestion.contains("-Z"), "{}", z.suggestion);
    let watcom = findings(16, Z_REBUILD, Z_ORIGINAL, "watcom");
    assert!(
        !rules(&watcom).contains(&"turbo-c-z"),
        "{:?}",
        rules(&watcom)
    );
}

#[test]
fn extra_jump_in_the_rebuild() {
    // mov ax,1; jmp short $+2; ret  against  mov ax,1; ret
    let f = findings(
        16,
        &[0xB8, 0x01, 0x00, 0xEB, 0x00, 0xC3],
        &[0xB8, 0x01, 0x00, 0xC3],
        "turbo-c",
    );
    let jump = find(&f, "extra-jump");
    assert_eq!(jump.text, "the rebuild has an extra jump (0003 jmp)");
    assert_eq!(jump.suggestion, "drop the else and return early");
}

#[test]
fn early_return_in_the_original() {
    // jmp short $+2; ret  against  xor ax,ax; jmp short $+2; ret
    let f = findings(
        16,
        &[0xEB, 0x00, 0xC3],
        &[0x31, 0xC0, 0xEB, 0x00, 0xC3],
        "turbo-c",
    );
    let early = find(&f, "early-return");
    assert!(
        early
            .text
            .starts_with("the original sets the return value before a jump to the end (0000 xor"),
        "{}",
        early.text
    );
}

#[test]
fn constant_names_both_values() {
    // mov ax,5; ret  against  mov ax,7; ret
    let f = findings(
        16,
        &[0xB8, 0x05, 0x00, 0xC3],
        &[0xB8, 0x07, 0x00, 0xC3],
        "turbo-c",
    );
    assert_eq!(rules(&f), ["constant"]);
    assert_eq!(
        f[0].text,
        "immediate differs: 0000: rebuild 0x5 (5), original 0x7 (7)"
    );
}

#[test]
fn sign_extension_signed_against_unsigned() {
    // cbw; ret  against  xor ah,ah; ret
    let f = findings(16, &[0x98, 0xC3], &[0x32, 0xE4, 0xC3], "turbo-c");
    let sign = find(&f, "sign-extension");
    assert_eq!(
        sign.text,
        "the rebuild extends with sign, the original without"
    );
}

#[test]
fn extra_register_saved_by_the_rebuild() {
    // push si; pop si; ret  against  ret
    let f = findings(16, &[0x56, 0x5E, 0xC3], &[0xC3], "turbo-c");
    let saved = find(&f, "extra-register");
    assert_eq!(saved.text, "the rebuild additionally saves si");
}

#[test]
fn load_order_of_parameters() {
    // mov ax,[bp+4]; mov dx,[bp+6]; ret  against  mov ax,[bp+6]; mov dx,[bp+4]; ret
    let f = findings(
        16,
        &[0x8B, 0x46, 0x04, 0x8B, 0x56, 0x06, 0xC3],
        &[0x8B, 0x46, 0x06, 0x8B, 0x56, 0x04, 0xC3],
        "turbo-c",
    );
    let load = find(&f, "load-order");
    assert_eq!(
        load.text,
        "parameters loaded in another order (rebuild [bp+4], [bp+6]; original [bp+6], [bp+4])"
    );
}

#[test]
fn operand_swap_of_the_same_instructions() {
    // mov ax,dx; add ax,bx; ret  against  mov ax,bx; add ax,dx; ret
    let f = findings(
        16,
        &[0x8B, 0xC2, 0x03, 0xC3, 0xC3],
        &[0x8B, 0xC3, 0x03, 0xC2, 0xC3],
        "turbo-c",
    );
    let swap = find(&f, "operand-swap");
    assert_eq!(
        swap.text,
        "same instructions and operands in another order (from rebuild 0000, original 0000)"
    );
}

#[test]
fn address_arithmetic_beforehand_in_the_original() {
    // mov eax,[eax*4+10h]; ret  against  shl eax,2; mov eax,[eax+10h]; ret
    let f = findings(
        32,
        &[0x8B, 0x04, 0x85, 0x10, 0x00, 0x00, 0x00, 0xC3],
        &[0xC1, 0xE0, 0x02, 0x8B, 0x80, 0x10, 0x00, 0x00, 0x00, 0xC3],
        "watcom",
    );
    let address = find(&f, "address-arithmetic");
    assert_eq!(
        address.text,
        "the original computes the element address beforehand, the rebuild indexes in the memory access"
    );
}

#[test]
fn jump_width_only() {
    // jmp short to ret; mov ax,1; ret  against  jmp near to ret; mov ax,1; ret
    let p = pairs(
        16,
        &[0xEB, 0x03, 0xB8, 0x01, 0x00, 0xC3],
        &[0xE9, 0x03, 0x00, 0xB8, 0x01, 0x00, 0xC3],
    );
    assert_eq!(p[0].kind, PairKind::Form);
    let f = diagnose(&p, 16, "turbo-c");
    assert_eq!(rules(&f), ["jump-width"]);
}

#[test]
fn length_end_more_instructions_in_the_rebuild() {
    // mov ax,1; ret; ret  against  mov ax,1; ret
    let f = findings(
        16,
        &[0xB8, 0x01, 0x00, 0xC3, 0xC3],
        &[0xB8, 0x01, 0x00, 0xC3],
        "turbo-c",
    );
    let end = find(&f, "length-end");
    assert_eq!(end.text, "the rebuild has 1 more instruction(s) at the end");
}

#[test]
fn classify_stack_only() {
    let (kind, n) = classify_deviation(&pairs(16, SWAPPED_REBUILD, SWAPPED_ORIGINAL)).unwrap();
    assert_eq!((kind, n), (DeviationKind::StackOnly, 2));
    assert_eq!(kind.id(), "stack");
}

#[test]
fn classify_registers_with_copy() {
    // mov ax,[bp-2]; add ax,[bp+4]; mov dx,ax; ret  against  mov dx,[bp-2]; add dx,[bp+4]; ret
    let p = pairs(
        16,
        &[0x8B, 0x46, 0xFE, 0x03, 0x46, 0x04, 0x8B, 0xD0, 0xC3],
        &[0x8B, 0x56, 0xFE, 0x03, 0x56, 0x04, 0xC3],
    );
    let (kind, n) = classify_deviation(&p).unwrap();
    assert_eq!((kind, n), (DeviationKind::RegistersOnly, 3));
    assert_eq!(kind.id(), "registers");
}

#[test]
fn classify_other_difference_is_none() {
    let p = pairs(16, &[0xB8, 0x05, 0x00, 0xC3], &[0xB8, 0x07, 0x00, 0xC3]);
    assert!(classify_deviation(&p).is_none());
}

#[test]
fn pairs_text_marks_and_collapses() {
    // ten equal instructions, then one differing
    let mut rebuild = vec![0x90u8; 10];
    rebuild.extend_from_slice(&[0xB8, 0x05, 0x00, 0xC3]);
    let mut original = vec![0x90u8; 10];
    original.extend_from_slice(&[0xB8, 0x07, 0x00, 0xC3]);
    let text = pairs_text(&pairs(16, &rebuild, &original));
    assert!(text.contains("… 7 equal instructions"), "{text}");
    assert!(text.contains("≠ 000A mov ax,5"), "{text}");
    assert!(text.contains("= 000D ret"), "{text}");
    assert!(
        text.lines().last().unwrap().contains("1 differing"),
        "{text}"
    );
}

const FRAME: &[u8] = &[0x55, 0x8B, 0xEC];

#[test]
fn classify_code_assembly_by_strong_insn() {
    // push bp; mov bp,sp; pusha; popa; pop bp; ret
    let (stage, reasons) = classify_code(
        &[0x55, 0x8B, 0xEC, 0x60, 0x61, 0x5D, 0xC3],
        16,
        FRAME,
        false,
        None,
    );
    assert_eq!(stage, Stage::Assembly);
    assert_eq!(stage.id(), "assembly");
    assert_eq!(reasons, ["instructions as in assembler: pusha, popa"]);
}

#[test]
fn classify_code_no_frame_and_weak() {
    // cli; sti; ret
    let (stage, reasons) = classify_code(&[0xFA, 0xFB, 0xC3], 16, FRAME, false, None);
    assert_eq!(stage, Stage::Assembly);
    assert_eq!(
        reasons,
        [
            "no standard frame (55 8b ec)",
            "rarely from the compiler: cli, sti"
        ]
    );
    // with the frame a weak reason alone does not make it assembly
    let (stage, reasons) = classify_code(
        &[0x55, 0x8B, 0xEC, 0xFA, 0x5D, 0xC3],
        16,
        FRAME,
        false,
        None,
    );
    assert_eq!(stage, Stage::Rebuildable);
    assert_eq!(reasons, ["rarely from the compiler: cli"]);
}

#[test]
fn classify_code_library() {
    let (stage, reasons) = classify_code(&[0xC3], 16, FRAME, true, None);
    assert_eq!(stage, Stage::Library);
    assert_eq!(reasons, ["named as a library function by signature"]);
    let (stage, reasons) = classify_code(&[0xC3], 16, FRAME, false, Some("tc-cl"));
    assert_eq!(stage, Stage::Library);
    assert_eq!(reasons, ["library code by pattern: tc-cl"]);
    assert_eq!(
        classify_code(&[], 16, FRAME, false, None),
        (Stage::Rebuildable, vec![])
    );
}

#[test]
fn malformed_code_does_not_panic() {
    let junk: Vec<u8> = (0..=255u8).collect();
    let _ = classify_code(&junk, 32, FRAME, false, None);
    let _ = classify_code(&junk, 7, FRAME, false, None);
    let f = findings(16, &junk[..64], &junk[64..140], "turbo-c");
    let _ = f;
}

#[test]
fn module_comparison_records_rule_ids_only_when_asked() {
    let (rebuild, original) = (&[0xB8, 0x05, 0x00, 0xC3][..], &[0xB8, 0x07, 0x00, 0xC3][..]);
    let m = ObjectModule::new(
        "t.c",
        vec![Section::new(
            "_TEXT",
            "CODE",
            SectionKind::Code,
            16,
            rebuild.to_vec(),
            vec![],
        )],
        vec![ObjSymbol::new("_f", 0, 0, true)],
    );
    let fs = functions(&m);
    let placement = Placement::new(fs[0].clone(), AT16, Some(4));
    let program = program(16, original);
    let decoration = Decoration::new("_{name}", "_{name}");
    let run = |options: &ModuleOptions| {
        compare_module(
            std::slice::from_ref(&placement),
            &program,
            &NoSymbols,
            &decoration,
            options,
        )
        .functions
        .remove(0)
    };
    let plain = run(&ModuleOptions::default());
    assert!(plain.diagnoses.is_empty());
    let asked = run(&ModuleOptions::default().with_diagnosis("turbo-c"));
    assert_eq!(asked.diagnoses, ["constant"]);
    assert_eq!(asked.metrics, plain.metrics);
    assert_eq!(asked.blockers, plain.blockers);
}

#[test]
fn classify_size_change_is_none() {
    // mov byte ptr [ebp-4],0; ret  against  mov dword ptr [ebp-8],0; ret: a type difference, not a slot
    let p = pairs(
        32,
        &[0xC6, 0x45, 0xFC, 0x00, 0xC3],
        &[0xC7, 0x45, 0xF8, 0x00, 0x00, 0x00, 0x00, 0xC3],
    );
    assert_eq!(p[0].kind, PairKind::Different);
    assert!(classify_deviation(&p).is_none());
}

#[test]
fn classify_parameter_slot_is_none() {
    // mov ax,[bp+4]; ret  against  mov ax,[bp+6]; ret: another parameter, not a local slot
    let p = pairs(16, &[0x8B, 0x46, 0x04, 0xC3], &[0x8B, 0x46, 0x06, 0xC3]);
    assert!(classify_deviation(&p).is_none());
}

#[test]
fn constant_needs_the_same_operand_size() {
    // mov byte ptr [ebp-4],5; ret  against  mov word ptr [ebp-4],7; ret
    let f = findings(
        32,
        &[0xC6, 0x45, 0xFC, 0x05, 0xC3],
        &[0x66, 0xC7, 0x45, 0xFC, 0x07, 0x00, 0xC3],
        "watcom",
    );
    assert!(!rules(&f).contains(&"constant"), "{:?}", rules(&f));
    // the same size: a constant difference
    let f = findings(
        32,
        &[0xC6, 0x45, 0xFC, 0x05, 0xC3],
        &[0xC6, 0x45, 0xFC, 0x07, 0xC3],
        "watcom",
    );
    assert_eq!(rules(&f), ["constant"]);
}
