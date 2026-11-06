//! Function-level attempts: the definition finder, splicing one function into its file and shrinking a file to the
//! functions one function's code depends on (port of Decomp's `nachbau/einzeln.py`).

use decovery_toolchain::{definitions, shrink, splice_function};

const FILE: &str = "\
#include \"t.h\"
#define BODY(x) { return x; }
#define LONG(x) \\
    { return x; }

static int helper(int a);
int table_user(void);

int leaf(int a)
{
    return a + 1;
}

int middle(int a)
{
    return leaf(a) * 2;
}

int target(int a)
{
    if (a) {
        return middle(a);
    }
    return 0;
}

int other(int a)
{
    return a - 1;
}
";

fn names(text: &str) -> Vec<String> {
    definitions(text).into_iter().map(|d| d.name).collect()
}

fn lines(text: &str) -> usize {
    text.matches('\n').count()
}

#[test]
fn definitions_skip_preprocessor_bodies() {
    assert_eq!(names(FILE), ["leaf", "middle", "target", "other"]);
    let defs = definitions(FILE);
    let leaf = &defs[0];
    assert_eq!(&FILE[leaf.start..leaf.brace], "int leaf(int a)\n");
    assert_eq!(&FILE[leaf.brace..leaf.end], "{\n    return a + 1;\n}\n");
    assert!(!leaf.knr && !leaf.is_static);

    // return type on a line of its own, K&R parameters, static, one-line definitions with `=` inside
    let text = "static\nint\nquiet(void) { int x = 1; return x; }\nlong old(a, b)\nint a;\nchar *b;\n{\n    return a;\n}\n/* f(void) { } */\nint t[] = { 1, 2 };\nstruct s { int a; };\nint proto(int a);\n";
    let defs = definitions(text);
    let found: Vec<(&str, bool, bool)> = defs
        .iter()
        .map(|d| (d.name.as_str(), d.knr, d.is_static))
        .collect();
    assert_eq!(found, [("quiet", false, true), ("old", true, false)]);
    assert_eq!(defs[0].start, 0, "the head starts at the return type");
}

#[test]
fn splice_replaces_definition() {
    let new = "int middle(int a)\n{\n    return leaf(a) * 3;\n}\n";
    let spliced = splice_function(FILE, "middle", new).unwrap();
    assert!(spliced.contains("return leaf(a) * 3;"));
    assert!(!spliced.contains("return leaf(a) * 2;"));
    assert_eq!(names(&spliced), ["leaf", "middle", "target", "other"]);
    // everything else stays
    let old = "int middle(int a)\n{\n    return leaf(a) * 2;\n}\n";
    assert_eq!(spliced.replace(new, old), FILE);
    // a source without a final line end does not glue the next line to the function
    let spliced = splice_function(FILE, "middle", new.trim_end()).unwrap();
    assert_eq!(spliced.replace(new, old), FILE);
}

#[test]
fn splice_rejects_missing_function() {
    let new = "int nosuch(int a)\n{\n    return a;\n}\n";
    let error = splice_function(FILE, "nosuch", new)
        .unwrap_err()
        .to_string();
    assert!(error.contains("nosuch"), "{error}");
    // the source must define the function it is spliced for
    let error = splice_function(FILE, "middle", "int leaf(int a) { return a; }\n")
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("middle") && error.contains("leaf"),
        "{error}"
    );
    let error = splice_function(FILE, "middle", "int middle(int a);\n")
        .unwrap_err()
        .to_string();
    assert!(error.contains("middle"), "{error}");
}

#[test]
fn splice_rejects_two_definitions() {
    let two = "int middle(int a)\n{\n    return a;\n}\nint extra(void)\n{\n    return 0;\n}\n";
    let error = splice_function(FILE, "middle", two)
        .unwrap_err()
        .to_string();
    assert!(
        error.contains("exactly one") && error.contains("extra"),
        "{error}"
    );
    // a file defining the function twice (`#if` branches) is ambiguous
    let twice = "#if A\nint f(void) { return 1; }\n#else\nint f(void) { return 2; }\n#endif\n";
    let error = splice_function(twice, "f", "int f(void) { return 3; }\n")
        .unwrap_err()
        .to_string();
    assert!(error.contains("2 times"), "{error}");
}

#[test]
fn shrink_keeps_callees_transitively() {
    let shrunk = shrink(FILE, &["target"]).unwrap();
    assert_eq!(shrunk.kept, ["leaf", "middle", "target"]);
    assert_eq!(shrunk.dropped, ["other"]);
    assert!(shrunk.text.contains("int other(int a);"));
    assert!(!shrunk.text.contains("return a - 1;"));
    assert!(shrunk.text.contains("return leaf(a) * 2;"));
    // the text outside function bodies stays
    assert!(
        shrunk
            .text
            .starts_with("#include \"t.h\"\n#define BODY(x) { return x; }\n")
    );
    // a function the target does not need
    let shrunk = shrink(FILE, &["leaf"]).unwrap();
    assert_eq!(shrunk.kept, ["leaf"]);
    assert_eq!(shrunk.dropped, ["middle", "target", "other"]);
    // nothing to drop, or the target is not defined exactly once
    assert!(shrink("int f(void) { return 0; }\n", &["f"]).is_none());
    assert!(shrink(FILE, &["nosuch"]).is_none());
}

#[test]
fn shrink_keeps_line_numbers() {
    let shrunk = shrink(FILE, &["leaf"]).unwrap();
    assert_eq!(lines(&shrunk.text), lines(FILE));
    let at = |text: &str, needle: &str| {
        text.lines()
            .position(|l| l.contains(needle))
            .unwrap_or_else(|| panic!("{needle} not in {text}"))
    };
    assert_eq!(
        at(&shrunk.text, "int other(int a);"),
        at(FILE, "int other(int a)")
    );
    assert_eq!(at(&shrunk.text, "return a + 1;"), at(FILE, "return a + 1;"));
    // a comment at the end of the head: the `;` goes behind it, the lines still match
    let text = "int g(void) /* doc */\n{\n    return 2;\n}\nint f(void)\n{\n    return 1;\n}\n";
    let shrunk = shrink(text, &["f"]).unwrap();
    assert_eq!(lines(&shrunk.text), lines(text));
    assert_eq!(at(&shrunk.text, "return 1;"), at(text, "return 1;"));
    assert!(
        shrunk.text.starts_with("int g(void) /* doc */\n;"),
        "{}",
        shrunk.text
    );
}

#[test]
fn shrink_keeps_knr_and_statics_named_outside_bodies() {
    let text = "\
static int handler(int a);
static int unused(int a);
int (*handlers[])(int) = { handler };

static int handler(int a)
{
    return a;
}

static int unused(int a)
{
    return a;
}

int old(a)
int a;
{
    return a;
}

int f(void)
{
    return 0;
}
";
    let shrunk = shrink(text, &["f"]).unwrap();
    // `handler` is named in the table (its prototype does not count), `old` has K&R parameters
    assert_eq!(shrunk.kept, ["handler", "old", "f"]);
    assert_eq!(shrunk.dropped, ["unused"]);
    assert_eq!(lines(&shrunk.text), lines(text));
}
