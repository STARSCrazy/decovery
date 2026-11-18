//! Similarity algorithms on hand-built bytes and sequences (no private data).

use decovery_diff::{
    HASHES, WINDOW, coarse_forms, coverage, indel_similarity, instruction_forms, lsh_keys, minhash,
    rank, shared_stretches,
};

#[test]
fn forms_normalise_numbers_and_registers() {
    // 32-bit: mov eax,[ebp+8]; mov ecx,[ebp-0Ch]; add esp,10h; mov dl,5; ret
    let code32 = [
        0x8B, 0x45, 0x08, 0x8B, 0x4D, 0xF4, 0x83, 0xC4, 0x10, 0xB2, 0x05, 0xC3,
    ];
    let forms = instruction_forms(&code32, 32, 0x1000);
    assert_eq!(
        forms,
        vec![
            "mov r,[ebp+N]",
            "mov r,[ebpN]",
            "add esp,N",
            "mov r8,N",
            "ret"
        ]
    );
    // 16-bit: mov ax,[bp+6]; mov bx,0FFFFh; push si; ret
    let code16 = [0x8B, 0x46, 0x06, 0xBB, 0xFF, 0xFF, 0x56, 0xC3];
    let forms = instruction_forms(&code16, 16, 0);
    assert_eq!(
        forms,
        vec!["mov r16,[bp+N]", "mov r16,N", "push r16", "ret"]
    );
    // Coarse forms keep the registers and mask numbers.
    let coarse = coarse_forms(&code32, 32, 0x1000);
    assert_eq!(coarse.len(), 5);
    assert!(coarse[0].contains("eax"), "{coarse:?}");
    assert!(!coarse[0].contains('8'), "{coarse:?}");
}

#[test]
fn short_and_near_jumps_share_a_form() {
    // Decomp's capstone text has no `short`/`near`: jmp rel8 and jmp rel32 are the same form there.
    // 32-bit: jmp short +0; jmp near +0; je short +0; je near +0
    let code = [
        0xEB, 0x00, 0xE9, 0x00, 0x00, 0x00, 0x00, 0x74, 0x00, 0x0F, 0x84, 0x00, 0x00, 0x00, 0x00,
    ];
    let forms = instruction_forms(&code, 32, 0x1000);
    assert_eq!(forms, vec!["jmp N", "jmp N", "je N", "je N"]);
}

#[test]
fn padding_is_dropped() {
    // ret; then int3/nop padding.
    let code = [0x55, 0xC3, 0x90, 0x90, 0x90];
    let forms = instruction_forms(&code, 32, 0);
    assert_eq!(forms, vec!["push ebp", "ret"]);
    assert_eq!(coarse_forms(&code, 32, 0).len(), 2);
}

#[test]
fn coverage_of_identical_sequences_is_one() {
    let a: Vec<u32> = (0..20).collect();
    assert_eq!(coverage(&a, &a), 1.0);
    let short = [1, 2, 3];
    assert_eq!(coverage(&short, &short), 1.0);
}

#[test]
fn coverage_short_candidate_is_zero() {
    let a: Vec<u32> = (0..20).collect();
    assert_eq!(coverage(&a, &a[..WINDOW - 1]), 0.0);
    // Half covered: first 10 of 20 shared.
    let mut b: Vec<u32> = (0..10).collect();
    b.extend(100..110);
    assert_eq!(coverage(&a, &b), 0.5);
}

#[test]
fn indel_matches_reference_values() {
    assert_eq!(indel_similarity(&[], &[]), 1.0);
    // LCS("ABCBDAB","BDCABA") = 4 -> 8/13
    let a = [1, 2, 3, 2, 4, 1, 2];
    let b = [2, 4, 3, 1, 2, 1];
    assert!((indel_similarity(&a, &b) - 8.0 / 13.0).abs() < 1e-12);
    // LCS = 0
    assert_eq!(indel_similarity(&[1, 2], &[3]), 0.0);
    // LCS([1,2,3,4],[1,3,4,5]) = 3 -> 6/8
    assert_eq!(indel_similarity(&[1, 2, 3, 4], &[1, 3, 4, 5]), 0.75);
}

/// Ruling P(T12)(c): the top three stretches by length, returned sorted by position (as Decomp does).
#[test]
fn stretches_top_three_longest_sorted_by_position() {
    // target: four shared runs of lengths 6, 9, 7, 8, separated by unique values.
    let mut t = Vec::new();
    let mut c = Vec::new();
    let mut next = 1000;
    for (k, len) in [6u32, 9, 7, 8].into_iter().enumerate() {
        let run: Vec<u32> = (0..len).map(|x| (k as u32) * 100 + x).collect();
        t.extend(&run);
        t.push(next);
        next += 1;
        c.push(next);
        next += 1;
        c.extend(&run);
    }
    let s = shared_stretches(&t, &c);
    assert_eq!(s.len(), 3);
    let lens: Vec<usize> = s.iter().map(|s| s.target.1 - s.target.0 + 1).collect();
    assert_eq!(lens, vec![9, 7, 8]);
    assert!(s.windows(2).all(|w| w[0].target.0 < w[1].target.0));
    for st in &s {
        assert_eq!(
            t[st.target.0..=st.target.1],
            c[st.candidate.0..=st.candidate.1]
        );
    }
}

#[test]
fn twin_detected_on_coarse_equality() {
    let t: Vec<u32> = (0..10).collect();
    let tc: Vec<u32> = (50..60).collect();
    let other_coarse: Vec<u32> = (70..80).collect();
    let cands: Vec<(&[u32], &[u32])> = vec![(&t, &other_coarse), (&t, &tc)];
    let r = rank(&t, &tc, &cands, 3);
    assert_eq!(r.len(), 2);
    let twin: Vec<(usize, bool)> = r.iter().map(|r| (r.candidate, r.twin)).collect();
    assert!(twin.contains(&(0, false)) && twin.contains(&(1, true)));
}

/// Ruling P(T12)(a)/(b): coverage rounded to 3 decimals before the score; ties keep the preselection order
/// (coverage, then smaller length difference), not the candidate index.
#[test]
fn rank_orders_by_score_then_preselection() {
    let t: Vec<u32> = (0..12).collect();
    let tc = t.clone();
    let half: Vec<u32> = (0..6).chain(200..206).collect();
    let far: Vec<u32> = (300..312).collect();
    // Same score as `half` would be, but differing length: a tie broken by preselection, not index.
    let mut longer: Vec<u32> = (0..6).collect();
    longer.extend(400..408);
    let cands: Vec<(&[u32], &[u32])> =
        vec![(&far, &far), (&longer, &longer), (&half, &half), (&t, &t)];
    let r = rank(&t, &tc, &cands, 10);
    assert_eq!(r[0].candidate, 3);
    assert_eq!(r[0].score, 1.0);
    assert!(r[0].twin);
    assert_eq!(r.last().unwrap().candidate, 0);
    for w in r.windows(2) {
        assert!(w[0].score >= w[1].score);
    }
    for x in &r {
        assert_eq!((x.coverage * 1000.0).round() / 1000.0, x.coverage);
        assert_eq!((x.similarity * 1000.0).round() / 1000.0, x.similarity);
    }
    // top limits the output.
    assert_eq!(rank(&t, &tc, &cands, 2).len(), 2);
    assert!(rank(&[], &[], &cands, 3).is_empty());
}

#[test]
fn rank_tie_keeps_preselection_order() {
    // Both score 0.25 (coverage 0, similarity 0.5); `g` has no length difference and is preselected before
    // `e`, so it stays first although its index is higher.
    let t: Vec<u32> = (1..=8).collect();
    let e: Vec<u32> = vec![1, 2, 3, 50]; // LCS 3 -> 6/12
    let g: Vec<u32> = vec![1, 2, 3, 4, 51, 52, 53, 54]; // LCS 4 -> 8/16
    let cands: Vec<(&[u32], &[u32])> = vec![(&e, &e), (&g, &g)];
    let r = rank(&t, &t, &cands, 2);
    assert_eq!(r[0].score, r[1].score);
    assert_eq!(r[0].candidate, 1, "{r:?}");
    assert_eq!(r[1].candidate, 0, "{r:?}");
}

#[test]
fn similar_sketches_share_an_lsh_key() {
    let a: Vec<u32> = (0..60).collect();
    let mut b = a.clone();
    b[30] = 999;
    let ka = lsh_keys(&minhash(&a));
    let kb = lsh_keys(&minhash(&b));
    assert!(ka.iter().zip(kb.iter()).any(|(x, y)| x == y));
    let far: Vec<u32> = (1000..1060).collect();
    let kf = lsh_keys(&minhash(&far));
    assert!(!ka.iter().zip(kf.iter()).any(|(x, y)| x == y));
}

#[test]
fn minhash_is_deterministic() {
    let a: Vec<u32> = (0..40).map(|x| x * 7 % 13).collect();
    let s1 = minhash(&a);
    assert_eq!(s1, minhash(&a));
    assert_eq!(s1.len(), HASHES);
    assert_ne!(minhash(&[1, 2, 3]), minhash(&[1, 2, 4]));
    // Fewer forms than a window: a single gram, still a full sketch.
    assert_eq!(minhash(&[1, 2, 3]), minhash(&[1, 2, 3]));
    let _ = minhash(&[]);
}
