use super::{AnalysisContext, Builder};

pub(super) fn apply(b: &mut Builder<'_>, ctx: &AnalysisContext) {
    let name = b
        .file
        .path
        .rsplit('/')
        .next()
        .unwrap_or("")
        .trim_end_matches(".go");
    let os = [
        "aix",
        "android",
        "darwin",
        "dragonfly",
        "freebsd",
        "hurd",
        "illumos",
        "ios",
        "js",
        "linux",
        "netbsd",
        "openbsd",
        "plan9",
        "solaris",
        "wasip1",
        "windows",
    ];
    let arch = [
        "386", "amd64", "amd64p32", "arm", "arm64", "loong64", "mips", "mipsle", "mips64",
        "mips64le", "ppc64", "ppc64le", "riscv64", "s390x", "sparc64", "wasm",
    ];
    let name = name.trim_end_matches("_test");
    let suffix: Vec<_> = name.split('_').collect();
    let mut reasons = vec![];
    if name.starts_with(['.', '_']) {
        reasons.push("variant_ignored_filename".into());
    }
    if suffix.len() > 1 {
        let last = suffix[suffix.len() - 1];
        if os.contains(&last) && last != ctx.goos {
            reasons.push(format!("variant_filename:goos={last}"));
        }
        if arch.contains(&last) {
            if last != ctx.goarch {
                reasons.push(format!("variant_filename:goarch={last}"));
            }
            if suffix.len() > 2 {
                let prev = suffix[suffix.len() - 2];
                if os.contains(&prev) && prev != ctx.goos {
                    reasons.push(format!("variant_filename:goos={prev}"));
                }
            }
        }
    }
    if b.file.path.ends_with("_test.go") && !ctx.include_tests {
        reasons.push("test_variant_not_requested".into());
    }
    let leading = header_line_comments(b.source);
    let modern: Vec<_> = leading
        .iter()
        .filter_map(|l| {
            l.trim()
                .strip_prefix("//go:build ")
                .or_else(|| l.trim().strip_prefix("//go:build\t"))
        })
        .collect();
    if modern.len() > 1 {
        reasons.push("invalid_build_constraint".into());
    }
    for expression in &modern {
        match expression_value(expression, ctx) {
            Some(true) => {}
            Some(false) => reasons.push(format!("variant_build_constraint:{}", expression.trim())),
            None => reasons.push("invalid_build_constraint".into()),
        }
    }
    if modern.is_empty() {
        for l in &leading {
            if let Some(line) = l.trim().strip_prefix("// +build ") {
                let selected = line.split_whitespace().any(|term| {
                    term.split(',').all(|tag| {
                        tag.strip_prefix('!')
                            .map_or_else(|| tag_value(tag, ctx), |x| !tag_value(x, ctx))
                    })
                });
                if !selected {
                    reasons.push(format!("variant_legacy_build_constraint:{line}"));
                }
            }
        }
    }
    if b.file.imports.iter().any(|i| i.module == "C") {
        if !ctx.cgo {
            reasons.push("cgo_disabled".into());
        }
        b.limit("cgo_type_binding_not_supported");
    }
    if !reasons.is_empty() {
        b.file.variant_status = "inactive".into();
        b.file.semantic_status = "not_requested".into();
        b.file.limitations.extend(reasons);
    }
}

/// Go directives are comment tokens before the package, not text inside block comments.
fn header_line_comments(source: &str) -> Vec<&str> {
    let mut rest = source.trim_start_matches('\u{feff}');
    let mut comments = vec![];
    loop {
        rest = rest.trim_start();
        if rest.starts_with("//") {
            let end = rest.find('\n').unwrap_or(rest.len());
            comments.push(&rest[..end]);
            rest = &rest[end..];
        } else if rest.starts_with("/*") {
            let Some(end) = rest.find("*/") else { break };
            rest = &rest[end + 2..];
        } else {
            break;
        }
    }
    comments
}

fn tag_value(tag: &str, c: &AnalysisContext) -> bool {
    tag == c.goos
        || tag == c.goarch
        || tag == "gc"
        || (tag == "cgo" && c.cgo)
        || c.build_tags.iter().any(|t| t == tag)
        || (tag == "unix" && !matches!(c.goos.as_str(), "windows" | "plan9" | "js" | "wasip1"))
        || (tag == "linux" && c.goos == "android")
        || (tag == "darwin" && c.goos == "ios")
        || (tag == "solaris" && c.goos == "illumos")
}
fn expression_value(text: &str, c: &AnalysisContext) -> Option<bool> {
    let mut tokens = vec![];
    let mut i = 0;
    let bytes = text.as_bytes();
    while i < bytes.len() {
        if bytes[i].is_ascii_whitespace() {
            i += 1;
            continue;
        }
        let start = i;
        if bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_' {
            while i < bytes.len()
                && (bytes[i].is_ascii_alphanumeric() || matches!(bytes[i], b'_' | b'.'))
            {
                i += 1;
            }
        } else if matches!(bytes[i], b'!' | b'(' | b')') {
            i += 1;
        } else if i + 1 < bytes.len()
            && ((bytes[i] == b'&' && bytes[i + 1] == b'&')
                || (bytes[i] == b'|' && bytes[i + 1] == b'|'))
        {
            i += 2;
        } else {
            return None;
        }
        tokens.push(&text[start..i]);
    }
    fn atom(t: &[&str], i: &mut usize, c: &AnalysisContext) -> Option<bool> {
        let v = *t.get(*i)?;
        *i += 1;
        match v {
            "!" => Some(!atom(t, i, c)?),
            "(" => {
                let x = or(t, i, c)?;
                if t.get(*i) != Some(&")") {
                    return None;
                }
                *i += 1;
                Some(x)
            }
            ")" | "&&" | "||" => None,
            _ => Some(tag_value(v, c)),
        }
    }
    fn and(t: &[&str], i: &mut usize, c: &AnalysisContext) -> Option<bool> {
        let mut x = atom(t, i, c)?;
        while t.get(*i) == Some(&"&&") {
            *i += 1;
            let rhs = atom(t, i, c)?;
            x = x && rhs;
        }
        Some(x)
    }
    fn or(t: &[&str], i: &mut usize, c: &AnalysisContext) -> Option<bool> {
        let mut x = and(t, i, c)?;
        while t.get(*i) == Some(&"||") {
            *i += 1;
            let rhs = and(t, i, c)?;
            x = x || rhs;
        }
        Some(x)
    }
    let mut i = 0;
    let value = or(&tokens, &mut i, c)?;
    (i == tokens.len()).then_some(value)
}
