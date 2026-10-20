use crate::text;
use kuchiki::{NodeRef, traits::TendrilSink};

pub(crate) fn document(html: &str) -> NodeRef {
    kuchiki::parse_html().one(html)
}

pub(crate) fn one(root: &NodeRef, selector: &str) -> Result<NodeRef, String> {
    root.select_first(selector)
        .map(|node| node.as_node().clone())
        .map_err(|_| format!("capture is missing {selector}"))
}

pub(crate) fn replace(node: &NodeRef, html: &str) {
    for child in node.children().collect::<Vec<_>>() {
        child.detach();
    }
    let fragment = document(&format!("<body>{html}</body>"));
    for child in one(&fragment, "body")
        .unwrap()
        .children()
        .collect::<Vec<_>>()
    {
        node.append(child);
    }
}

pub(crate) fn set_text(root: &NodeRef, selector: &str, value: &str) -> Result<(), String> {
    let node = one(root, selector)?;
    replace(&node, &text::escape(value));
    Ok(())
}
