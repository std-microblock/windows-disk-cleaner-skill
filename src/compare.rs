//! Full-fidelity scan validation, intentionally separate from the bounded display.
use crate::model::{HARDLINK, Snapshot};
use anyhow::Result;
use serde::Serialize;
use std::{collections::BTreeMap, path::Path};
#[derive(Serialize, Debug)]
pub struct Comparison {
    pub equal: bool,
    pub left_nodes: usize,
    pub right_nodes: usize,
    pub left_complete: bool,
    pub right_complete: bool,
    pub root_logical_equal: bool,
    pub root_allocated_equal: bool,
    pub differences: u64,
    pub examples: Vec<String>,
}
#[derive(Debug)]
struct Entry {
    oldest_modified_ms: i64,
    latest_modified_ms: i64,
    logical: u64,
    allocated: u64,
    is_dir: bool,
    hardlink: bool,
}
fn entries(s: &Snapshot, scope: u32) -> BTreeMap<Vec<u16>, Entry> {
    let mut out = BTreeMap::new();
    let mut stack = vec![(scope, Vec::new())];
    while let Some((id, key)) = stack.pop() {
        let n = &s.nodes[id as usize];
        for child in s.children(id) {
            let mut key = key.clone();
            if !key.is_empty() {
                key.push(92);
            }
            key.extend_from_slice(s.name_units(child));
            stack.push((child, key));
        }
        out.insert(
            key,
            Entry {
                oldest_modified_ms: n.oldest_modified_ms,
                latest_modified_ms: n.latest_modified_ms,
                logical: n.logical,
                allocated: n.allocated,
                is_dir: n.is_dir(),
                hardlink: n.flags & HARDLINK != 0,
            },
        );
    }
    out
}
pub fn compare(left: &Snapshot, right: &Snapshot, scope: &Path) -> Result<Comparison> {
    let a = entries(left, left.find(scope)?);
    let b = entries(right, right.find(scope)?);
    let ar = &a[&Vec::new()];
    let br = &b[&Vec::new()];
    let mut result = Comparison {
        equal: true,
        left_nodes: a.len(),
        right_nodes: b.len(),
        left_complete: left.stats.complete,
        right_complete: right.stats.complete,
        root_logical_equal: ar.logical == br.logical,
        root_allocated_equal: ar.allocated == br.allocated,
        differences: 0,
        examples: Vec::new(),
    };
    let mut difference = |text: String| {
        result.differences += 1;
        if result.examples.len() < 40 {
            result.examples.push(text);
        }
    };
    for (key, entry) in &a {
        match b.get(key) {
            None => difference(format!("only left: {}", String::from_utf16_lossy(key))),
            Some(other) => {
                if entry.oldest_modified_ms != other.oldest_modified_ms
                    || entry.latest_modified_ms != other.latest_modified_ms
                    || entry.logical != other.logical
                    || entry.is_dir != other.is_dir
                    || (!entry.is_dir
                        && !entry.hardlink
                        && !other.hardlink
                        && entry.allocated != other.allocated)
                {
                    difference(format!(
                        "{}: left={entry:?}; right={other:?}",
                        String::from_utf16_lossy(key)
                    ));
                }
            }
        }
    }
    for key in b.keys() {
        if !a.contains_key(key) {
            difference(format!("only right: {}", String::from_utf16_lossy(key)));
        }
    }
    result.equal =
        result.differences == 0 && result.root_logical_equal && result.root_allocated_equal;
    Ok(result)
}
