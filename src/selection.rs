//! Tree checkbox state, independent of pagination/expansion. A partially checked
//! directory is kept; only selected descendant objects are eligible for deletion.
use crate::model::{NONE, Snapshot};
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Tally {
    pub allocated: u64,
    pub logical: u64,
    pub files: u32,
    pub dirs: u32,
}
impl Tally {
    pub fn items(self) -> u64 {
        self.files as u64 + self.dirs as u64
    }
    pub(crate) fn add(self, other: Self) -> Self {
        Self {
            allocated: self.allocated + other.allocated,
            logical: self.logical + other.logical,
            files: self.files + other.files,
            dirs: self.dirs + other.dirs,
        }
    }
}
#[derive(Debug, Clone)]
pub struct TreeSelection {
    selected: Vec<bool>,
    totals: Vec<Tally>,
}
impl TreeSelection {
    pub fn all(tree: &Snapshot) -> Self {
        Self {
            selected: vec![true; tree.nodes.len()],
            totals: tree
                .nodes
                .iter()
                .map(|n| Tally {
                    allocated: n.allocated,
                    logical: n.logical,
                    files: n.files,
                    dirs: n.dirs,
                })
                .collect(),
        }
    }
    pub fn totals(&self, id: u32) -> Tally {
        self.totals[id as usize]
    }
    pub fn selected(&self, id: u32) -> bool {
        self.selected[id as usize]
    }
    pub fn bits(&self) -> Vec<bool> {
        self.selected.clone()
    }
    /// 0=unchecked, 1=partially checked, 2=whole subtree checked.
    pub fn state(&self, tree: &Snapshot, id: u32) -> i32 {
        let n = &tree.nodes[id as usize];
        let count = self.totals(id).items();
        if count == 0 {
            0
        } else if count == n.files as u64 + n.dirs as u64 {
            2
        } else {
            1
        }
    }
    pub fn set_subtree(&mut self, tree: &Snapshot, id: u32, checked: bool) {
        let mut stack = vec![id];
        while let Some(i) = stack.pop() {
            let n = &tree.nodes[i as usize];
            self.selected[i as usize] = checked;
            self.totals[i as usize] = if checked {
                Tally {
                    allocated: n.allocated,
                    logical: n.logical,
                    files: n.files,
                    dirs: n.dirs,
                }
            } else {
                Tally::default()
            };
            stack.extend(tree.children(i));
        }
        let mut parent = tree.nodes[id as usize].parent;
        while parent != NONE {
            let node = &tree.nodes[parent as usize];
            let (mut children_total, mut selected_total) = (Tally::default(), Tally::default());
            let mut all = true;
            for child in tree.children(parent) {
                let c = &tree.nodes[child as usize];
                children_total = children_total.add(Tally {
                    allocated: c.allocated,
                    logical: c.logical,
                    files: c.files,
                    dirs: c.dirs,
                });
                selected_total = selected_total.add(self.totals(child));
                all &= self.state(tree, child) == 2;
            }
            self.selected[parent as usize] = all;
            if all {
                selected_total = selected_total.add(Tally {
                    allocated: node.allocated.saturating_sub(children_total.allocated),
                    logical: node.logical.saturating_sub(children_total.logical),
                    files: u32::from(!node.is_dir()),
                    dirs: u32::from(node.is_dir()),
                });
            }
            self.totals[parent as usize] = selected_total;
            parent = node.parent;
        }
    }
    /// Top-level selected subtrees, so nested children are never double-counted.
    pub fn selected_roots(&self, tree: &Snapshot) -> Vec<u32> {
        let mut roots = Vec::new();
        let mut stack = vec![0];
        while let Some(id) = stack.pop() {
            if self.state(tree, id) == 2 {
                roots.push(id);
            } else if self.state(tree, id) == 1 {
                stack.extend(tree.children(id));
            }
        }
        roots
    }
    pub fn len(&self) -> usize {
        self.selected.len()
    }
    pub fn is_empty(&self) -> bool {
        self.selected.is_empty()
    }
}
