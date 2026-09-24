//! H02b frozen contract: G03 organic-eval accepted summaries are OKF v0.2
//! conformant.
//!
//! The codex V0.5 audit found 10 tracked `*.summary.md` evaluation artifacts
//! under `deliverables/g03-organic-eval/accepts/` (packets 06-10, 21-25)
//! without any OKF frontmatter. H02b prepended a minimal compliant
//! frontmatter (`type: knowledge`, `status: stable`,
//! `generated: {by: gtkg/g03-organic-eval}`) while omitting `generated.at`
//! because the retained evidence records only a date, not a trustworthy
//! timestamp. The migration keeps
//! keeping the original body bytes untouched; before→after SHA-256 pairs are
//! recorded in `deliverables/g03-organic-eval/evidence-manifest.json` and the
//! change is logged in the evaluation report `errata`.
//!
//! This contract freezes two invariants:
//! 1. every `*.summary.md` artifact in that directory parses with the
//!    official-compatible `parse_okf` and carries a non-empty `type`
//!    (SPEC §11(2));
//! 2. the body after the frontmatter still starts with the original
//!    `model:` generator header, i.e. the summary text was not rewritten.

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use gtkg_core::okf::{OkfStatus, parse_okf_concept};
use sha2::{Digest, Sha256};

fn accepts_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("deliverables/g03-organic-eval/accepts")
}

fn frozen_digests() -> BTreeMap<&'static str, (&'static str, &'static str)> {
    BTreeMap::from([
        (
            "06-crates__gtkg-core__src__lib.rs.summary.md",
            (
                "sha256:2104cc0a8c95a04f71b9e9d6e442d1161b37e6aebbc272e6e6acc11730ef59c4",
                "sha256:041811068f395cee49e3df088bbb322f36f1afed988cbb0f6c1a7c81c5d5d70e",
            ),
        ),
        (
            "07-crates__gtkg-core__src__no_db.rs.summary.md",
            (
                "sha256:32e80cae0e459fdbb6acbb0b1abc50e067b48197d94194759f3776a92a614365",
                "sha256:2be3854decbcc84de99cb88c4b2b412ed0aebd31388f75dd865bf4f0e82c44cc",
            ),
        ),
        (
            "08-crates__gtkg-core__src__template.rs.summary.md",
            (
                "sha256:a67b6c814d5e3e46daa73f925eecc70da8aba5c88f913bb3d065d3ffe66c3fa1",
                "sha256:3613b2f6a79d73326faeb94f4b05e35023bca1740eaa23a166e796ee23110852",
            ),
        ),
        (
            "09-crates__gtkg-extract__src__lib.rs.summary.md",
            (
                "sha256:095c814a2330d1afc5283984d96470528b37b6479fda2a8f2373057bfdf16f43",
                "sha256:485f203f7c3b75cf8dc55b3d421de9ec5c622ae54cb027bf3746ce0919a58d02",
            ),
        ),
        (
            "10-crates__gtkg-protocol__src__lib.rs.summary.md",
            (
                "sha256:60fcae1021007724a0df8afbbbcfa340f4210beb3e599314f0e04e5ae3aa0a72",
                "sha256:3fd6a83ba702bc2047cd030018e1ca768265a396fb09ffc77a9959b5ad2461e9",
            ),
        ),
        (
            "21-docs__文档知识图谱.md.summary.md",
            (
                "sha256:b0ac3a2de0a7759ee238292419a6e3008145f92f9e9483e622be82699906cf36",
                "sha256:00cca6823d42b4f3bea6dc1e18a47535d7df94053cac2adcc471d20fdee44a7e",
            ),
        ),
        (
            "22-skills__goal-team-knowledge-graph__references__workflows.md.summary.md",
            (
                "sha256:8274dad1ca994be75e0ebcb70a46c51b453fef3288becfd44acc10ee2a13d4d7",
                "sha256:353540bfeb9aef6d6f4a20d185aa8d3a312b258a4660b38a26bb3d0112b6cf13",
            ),
        ),
        (
            "23-templates__design-deliverables__versions__V0.1__architecture-template.md.summary.md",
            (
                "sha256:3d4839baba4e0a1188f671b01e298ed82a57ecd287cccd97f6aa4c723ecc6aa1",
                "sha256:1b62c048cdd896c2d79f4470b0eca62e55b85a138a8a5e586dfa7a36cc3be550",
            ),
        ),
        (
            "24-templates__design-deliverables__versions__V0.1__knowledge-wiki-prototype-template.md.summary.md",
            (
                "sha256:a0fc2abdddb4693d22156e3b1535fa0e1acc2e4426ee6ccf8797bef59008977e",
                "sha256:554a1f00adb7caed0dfba66a80e99def83bf3472a39931cdc067ace4b3e196f7",
            ),
        ),
        (
            "25-templates__design-deliverables__versions__index.md.summary.md",
            (
                "sha256:577cc273b53685808134c870dc58764d2c9b65d3336aefe470c482bdfab12f68",
                "sha256:819aa9aa063dd348937cb45e03f538048776dc77bdbf12180792547f412ff7b1",
            ),
        ),
    ])
}

fn digest(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

#[test]
fn g03_accepted_summaries_parse_as_okf_with_frontmatter() {
    let dir = accepts_dir();
    let mut names = Vec::new();
    for entry in fs::read_dir(&dir).expect("accepts dir readable") {
        let name = entry.expect("dir entry").file_name();
        let name = name.to_str().expect("utf-8 name").to_owned();
        if name.ends_with(".summary.md") {
            names.push(name);
        }
    }
    names.sort();
    let frozen = frozen_digests();
    assert_eq!(
        names,
        frozen
            .keys()
            .copied()
            .map(str::to_owned)
            .collect::<Vec<_>>(),
        "expected the 10 G03 accepted summaries, found {names:?}"
    );

    for name in &names {
        let path = dir.join(name);
        let source =
            fs::read_to_string(&path).unwrap_or_else(|error| panic!("{name} unreadable: {error}"));
        let &(expected_body, expected_file) = frozen.get(name.as_str()).expect("frozen digest");
        assert_eq!(digest(source.as_bytes()), expected_file, "{name} full file");
        assert!(
            source.starts_with("---\n"),
            "{name} must open with an OKF frontmatter block"
        );
        let document = parse_okf_concept(&source)
            .unwrap_or_else(|error| panic!("{name} must parse via parse_okf: {error}"));
        assert_eq!(
            document.frontmatter.kind, "knowledge",
            "{name} must declare the producer summary type"
        );
        assert_eq!(
            document.frontmatter.status,
            OkfStatus::Stable,
            "{name} must be lifecycle-stable"
        );
        let generated = document
            .frontmatter
            .generated
            .unwrap_or_else(|| panic!("{name} must record generation provenance"));
        assert_eq!(generated.by, "gtkg/g03-organic-eval", "{name}");
        assert!(
            generated.at.is_empty(),
            "{name} must not invent a midnight timestamp from a date-only record"
        );
        assert!(
            document.body.starts_with("model: "),
            "{name} body must retain the original generator header (bytes unchanged)"
        );
        let observed_body = digest(document.body.as_bytes());
        let first_difference = observed_body
            .bytes()
            .zip(expected_body.bytes())
            .position(|(observed, expected)| observed != expected);
        assert!(
            observed_body.as_bytes() == expected_body.as_bytes(),
            "{name} body must remain byte-identical to its pre-H02b summary: \
             observed={observed_body:?} expected={expected_body:?} \
             lengths={}/{} first_difference={first_difference:?}",
            observed_body.len(),
            expected_body.len()
        );
    }
}
