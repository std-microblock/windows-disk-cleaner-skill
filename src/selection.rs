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
#[cfg(test)]
mod tests {
    use super::*;
    use crate::{model::DIR, platform::VolumeInfo};
    fn tree() -> Snapshot {
        let mut t = Snapshot::new("C:/fixture".into(), VolumeInfo::default(), "test", 1);
        let d = t.push(0, &[100], 0, 0, DIR).unwrap();
        t.push(d, &[97], 10, 16, 0).unwrap();
        t.push(d, &[98], 20, 32, 0).unwrap();
        t.push(0, &[101], 0, 0, DIR).unwrap();
        t.finish().unwrap();
        t
    }
    #[test]
    fn folder_selects_every_descendant_not_just_visible_rows() {
        let t = tree();
        let mut s = TreeSelection::all(&t);
        s.set_subtree(&t, 0, false);
        assert_eq!(s.totals(0).items(), 0);
        s.set_subtree(&t, 1, true);
        assert!(s.selected(2) && s.selected(3));
        assert_eq!(s.totals(1).files, 2);
        assert_eq!(s.totals(1).allocated, 48);
        assert_eq!(s.state(&t, 0), 1);
        assert!(!s.selected(0));
        assert_eq!(s.selected_roots(&t), vec![1]);
    }
    #[test]
    fn deselected_child_is_preserved_and_parent_is_partial() {
        let t = tree();
        let mut s = TreeSelection::all(&t);
        s.set_subtree(&t, 2, false);
        assert_eq!(s.state(&t, 1), 1);
        assert!(!s.selected(1));
        assert!(!s.selected(2));
        assert_eq!(s.totals(1).allocated, 32);
        assert_eq!(s.totals(0).files, 1);
        s.set_subtree(&t, 2, true);
        assert_eq!(s.state(&t, 0), 2);
        assert_eq!(s.totals(0).allocated, 48);
    }
    #[test]
    fn empty_directories_remain_selectable() {
        let t = tree();
        let mut s = TreeSelection::all(&t);
        s.set_subtree(&t, 0, false);
        s.set_subtree(&t, 4, true);
        assert_eq!(s.state(&t, 4), 2);
        assert_eq!(s.totals(0).items(), 1);
        assert_eq!(s.totals(0).files, 0);
        assert!(!s.selected(0));
    }
}
