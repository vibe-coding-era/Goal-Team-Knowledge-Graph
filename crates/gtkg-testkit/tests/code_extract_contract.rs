use std::fs;

use gtkg_extract::extract_path;
use tempfile::tempdir;

#[test]
fn rust_python_typescript_and_javascript_emit_static_symbols_without_execution() {
    let temp = tempdir().expect("tempdir");
    let sentinel = temp.path().join("must-not-exist");
    let fixtures = [
        (
            "lib.rs",
            "pub struct Ledger;\npub fn reconcile() {}\n// touch must-not-exist\n",
            ["struct:Ledger", "function:reconcile"],
        ),
        (
            "agent.py",
            "class Planner:\n    pass\nasync def dispatch():\n    pass\n# touch must-not-exist\n",
            ["class:Planner", "function:dispatch"],
        ),
        (
            "view.ts",
            "export interface Surface {}\nexport function render() {}\n// touch must-not-exist\n",
            ["interface:Surface", "function:render"],
        ),
        (
            "worker.js",
            "class Worker {}\nconst execute = () => {};\n// touch must-not-exist\n",
            ["class:Worker", "binding:execute"],
        ),
    ];

    for (name, source, expected_symbols) in fixtures {
        let path = temp.path().join(name);
        fs::write(&path, source).expect("write code fixture");
        let extracted = extract_path(&path).expect("static code extraction");
        let symbols = extracted
            .observations
            .get("symbols")
            .expect("static symbol facts");
        for expected in expected_symbols {
            assert!(symbols.lines().any(|symbol| symbol == expected));
        }
        assert!(!extracted.executed_target_content);
        assert!(!sentinel.exists());
    }
}
