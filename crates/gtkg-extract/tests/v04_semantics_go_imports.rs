use gtkg_extract::v04::{AnalysisContext,extract};
#[test]
fn absent_alias_is_not_replaced_by_an_unproven_module_basename(){
    let src="package p\nimport (\n \"example/path\"\n path \"example/other\"\n alias \"example/renamed\"\n _ \"example/sideeffect\"\n . \"example/dot\"\n)\n";
    let f=extract("p/a.go",src.as_bytes(),&AnalysisContext::default()).unwrap();assert_eq!(f.parse_status,"parsed");
    let imports:Vec<_>=f.imports.iter().map(|i|(i.module.as_str(),i.alias.as_str())).collect();
    assert_eq!(imports,vec![("example/path",""),("example/other","path"),("example/renamed","alias"),("example/sideeffect","_"),("example/dot",".")]);
    for i in &f.imports{assert!(src[i.span.byte_start..i.span.byte_end].contains(&i.module));}
}
