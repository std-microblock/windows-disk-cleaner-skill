//! A view-only forest joining all staged targets under their drive and real path
//! ancestors. Group nodes can select targets, but are NEVER deletion objects.
//! Only ancestor nodes are added; the potentially millions of snapshot nodes stay
//! in the original compact indexes and are addressed by stable integer keys.
use crate::{
    model::Snapshot,
    platform,
    selection::{Tally, TreeSelection},
};
use anyhow::{Context, Result, ensure};
use std::{cell::RefCell, collections::BTreeMap, ffi::OsString, path::PathBuf, sync::Arc};

pub const PAGE_SIZE: usize = 200;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Location {
    Entry { target: usize, node: u32 },
    Group(usize),
}

#[derive(Debug)]
pub struct Group {
    pub path: PathBuf,
    pub name: String,
    pub drive: bool,
    pub children: Vec<i32>,
    /// Each target appears once in this group's summary, regardless of expansion.
    pub targets: Vec<usize>,
}

#[derive(Debug, Default)]
pub struct Forest {
    offsets: Vec<u32>,
    entry_count: u32,
    pub groups: Vec<Group>,
    pub roots: Vec<i32>,
    sorted_children: RefCell<BTreeMap<i32, Arc<[i32]>>>,
}

impl Forest {
    pub fn new(trees: &[&Snapshot]) -> Result<Self> {
        let mut offsets = Vec::with_capacity(trees.len() + 1);
        let mut total = 0u32;
        for tree in trees {
            offsets.push(total);
            total = total
                .checked_add(u32::try_from(tree.nodes.len())?)
                .context("too many review nodes")?;
        }
        offsets.push(total);
        ensure!(
            total <= i32::MAX as u32,
            "review tree exceeds UI index limits"
        );
        let mut forest = Self {
            offsets,
            entry_count: total,
            ..Self::default()
        };
        let mut groups_by_path = BTreeMap::<PathBuf, usize>::new();
        for (target, tree) in trees.iter().enumerate() {
            let root = PathBuf::from(platform::display_path(&tree.root));
            let drive = PathBuf::from(platform::display_path(&tree.volume.root));
            ensure!(
                drive.is_absolute() && root.is_absolute() && platform::within(&root, &drive),
                "target is not under its recorded local volume: {}",
                root.display()
            );
            let components: Vec<OsString> = root
                .components()
                .skip(drive.components().count())
                .map(|c| c.as_os_str().to_owned())
                .collect();
            ensure!(
                !components.is_empty(),
                "a volume root is not a deletion target"
            );
            let mut current_path = drive;
            let mut parent: Option<usize> = None;
            // Exclude the target itself: it already has a real node in its snapshot.
            for depth in 0..components.len() {
                if depth > 0 {
                    current_path.push(&components[depth - 1]);
                }
                let group_index = if let Some(&index) = groups_by_path.get(&current_path) {
                    index
                } else {
                    let index = forest.groups.len();
                    let key = forest.group_key(index)?;
                    let name = if depth == 0 {
                        platform::display_path(&current_path)
                    } else {
                        current_path
                            .file_name()
                            .unwrap()
                            .to_string_lossy()
                            .into_owned()
                    };
                    forest.groups.push(Group {
                        path: current_path.clone(),
                        name,
                        drive: depth == 0,
                        children: Vec::new(),
                        targets: Vec::new(),
                    });
                    groups_by_path.insert(current_path.clone(), index);
                    if let Some(parent) = parent {
                        forest.groups[parent].children.push(key);
                    } else {
                        forest.roots.push(key);
                    }
                    index
                };
                forest.groups[group_index].targets.push(target);
                parent = Some(group_index);
            }
            let key = forest
                .entry_key(target, 0)
                .context("invalid target root key")?;
            forest.groups[parent.unwrap()].children.push(key);
        }
        // A target's drive appears only once. Larger selected groups are not moved
        // around while checking rows; stable path order preserves user orientation.
        let mut roots = std::mem::take(&mut forest.roots);
        roots.sort_by(|&a, &b| {
            let Location::Group(a) = forest.locate(a).unwrap() else {
                unreachable!()
            };
            let Location::Group(b) = forest.locate(b).unwrap() else {
                unreachable!()
            };
            forest.groups[a].path.cmp(&forest.groups[b].path)
        });
        forest.roots = roots;
        Ok(forest)
    }

    pub fn entry_key(&self, target: usize, node: u32) -> Option<i32> {
        let start = *self.offsets.get(target)?;
        let end = *self.offsets.get(target + 1)?;
        let key = start.checked_add(node)?;
        (key < end).then_some(key as i32)
    }

    pub fn group_key(&self, index: usize) -> Result<i32> {
        let key = self
            .entry_count
            .checked_add(u32::try_from(index)?)
            .context("group key overflow")?;
        Ok(i32::try_from(key).context("too many ancestor groups")?)
    }

    pub fn locate(&self, key: i32) -> Option<Location> {
        let key = u32::try_from(key).ok()?;
        if key >= self.entry_count {
            let index = (key - self.entry_count) as usize;
            return (index < self.groups.len()).then_some(Location::Group(index));
        }
        let target = self
            .offsets
            .partition_point(|&start| start <= key)
            .checked_sub(1)?;
        self.offsets.get(target + 1)?;
        Some(Location::Entry {
            target,
            node: key - self.offsets[target],
        })
    }

    pub fn path(&self, trees: &[&Snapshot], key: i32) -> Option<PathBuf> {
        match self.locate(key)? {
            Location::Group(group) => Some(self.groups[group].path.clone()),
            Location::Entry { target, node } => Some(trees.get(target)?.path(node)),
        }
    }

    pub fn target_indices(&self, key: i32) -> Vec<usize> {
        match self.locate(key) {
            Some(Location::Group(group)) => self.groups[group].targets.clone(),
            Some(Location::Entry { target, .. }) => vec![target],
            None => Vec::new(),
        }
    }

    /// Aggregates only marked content. Drive/unmarked ancestor directories do NOT
    /// contribute files, bytes, or a removable directory object of their own.
    pub fn tally(
        &self,
        trees: &[&Snapshot],
        choices: &[TreeSelection],
        key: i32,
    ) -> (Tally, Tally) {
        match self.locate(key) {
            Some(Location::Entry { target, node }) => {
                let n = &trees[target].nodes[node as usize];
                (
                    choices[target].totals(node),
                    Tally {
                        allocated: n.allocated,
                        logical: n.logical,
                        files: n.files,
                        dirs: n.dirs,
                    },
                )
            }
            Some(Location::Group(group)) => {
                let mut selected = Tally::default();
                let mut total = Tally::default();
                for &target in &self.groups[group].targets {
                    let n = &trees[target].nodes[0];
                    selected = selected.add(choices[target].totals(0));
                    total = total.add(Tally {
                        allocated: n.allocated,
                        logical: n.logical,
                        files: n.files,
                        dirs: n.dirs,
                    });
                }
                (selected, total)
            }
            None => (Tally::default(), Tally::default()),
        }
    }

    pub fn check_state(&self, trees: &[&Snapshot], choices: &[TreeSelection], key: i32) -> i32 {
        let (selected, total) = self.tally(trees, choices, key);
        if selected.items() == 0 {
            0
        } else if selected.items() == total.items() {
            2
        } else {
            1
        }
    }

    pub fn check(
        &self,
        trees: &[&Snapshot],
        choices: &mut [TreeSelection],
        key: i32,
        checked: bool,
    ) {
        match self.locate(key) {
            Some(Location::Group(group)) => {
                for &target in &self.groups[group].targets {
                    choices[target].set_subtree(trees[target], 0, checked);
                }
            }
            Some(Location::Entry { target, node }) => {
                choices[target].set_subtree(trees[target], node, checked)
            }
            None => {}
        }
    }

    pub fn children(&self, trees: &[&Snapshot], key: i32) -> Arc<[i32]> {
        if let Some(cached) = self.sorted_children.borrow().get(&key) {
            return cached.clone();
        }
        let children: Vec<i32> = match self.locate(key) {
            Some(Location::Group(group)) => self.groups[group].children.clone(),
            Some(Location::Entry { target, node }) => trees[target]
                .children(node)
                .filter_map(|node| self.entry_key(target, node))
                .collect(),
            None => Vec::new(),
        };
        // Cache each expanded node's original order. A checkbox click must not
        // sort a million-entry directory again or allocate names per comparison.
        let mut decorated: Vec<_> = children
            .into_iter()
            .map(|key| {
                let (directory, bytes, name) = match self.locate(key).unwrap() {
                    Location::Group(g) => (
                        true,
                        self.groups[g]
                            .targets
                            .iter()
                            .map(|&t| trees[t].nodes[0].allocated)
                            .sum::<u64>(),
                        self.groups[g].name.encode_utf16().collect::<Vec<_>>(),
                    ),
                    Location::Entry { target, node } => {
                        let n = &trees[target].nodes[node as usize];
                        let name = if node == 0 {
                            platform::encode_name(
                                trees[target].root.file_name().unwrap_or_default(),
                            )
                        } else {
                            trees[target].name_units(node).to_vec()
                        };
                        (n.is_dir(), n.allocated, name)
                    }
                };
                (key, directory, bytes, name)
            })
            .collect();
        decorated.sort_unstable_by(|a, b| {
            b.1.cmp(&a.1)
                .then_with(|| b.2.cmp(&a.2))
                .then_with(|| a.3.cmp(&b.3))
        });
        let ordered: Arc<[i32]> = decorated
            .into_iter()
            .map(|d| d.0)
            .collect::<Vec<_>>()
            .into();
        self.sorted_children
            .borrow_mut()
            .insert(key, ordered.clone());
        ordered
    }

    /// Show the drive and each path leading to a target, but keep target contents
    /// collapsed initially. Expanded groups never affect the selection itself.
    pub fn initial_expansion(&self) -> BTreeMap<i32, usize> {
        self.groups
            .iter()
            .enumerate()
            .map(|(i, g)| (self.group_key(i).unwrap(), PAGE_SIZE.max(g.children.len())))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{model::DIR, platform::VolumeInfo};
    fn tree(root: &str, volume: &str, bytes: u64) -> Snapshot {
        let mut s = Snapshot::new(
            root.into(),
            VolumeInfo {
                root: volume.into(),
                ..Default::default()
            },
            "test",
            1,
        );
        s.push(
            0,
            &"one.bin".encode_utf16().collect::<Vec<_>>(),
            bytes,
            bytes,
            0,
        )
        .unwrap();
        s.push(0, &"empty".encode_utf16().collect::<Vec<_>>(), 0, 0, DIR)
            .unwrap();
        s.finish().unwrap();
        s
    }
    #[test]
    fn merges_same_drive_and_shared_ancestors() {
        let a = tree("D:/Projects/app/target", "D:/", 10);
        let b = tree("D:/Projects/app/cache", "D:/", 20);
        let c = tree("C:/Downloads/archive", "C:/", 30);
        let trees = [&a, &b, &c];
        let forest = Forest::new(&trees).unwrap();
        assert_eq!(forest.roots.len(), 2);
        let d = forest
            .groups
            .iter()
            .position(|g| g.path == PathBuf::from("D:/"))
            .unwrap();
        let app = forest
            .groups
            .iter()
            .find(|g| g.path == PathBuf::from("D:/Projects/app"))
            .unwrap();
        assert_eq!(app.children.len(), 2);
        assert_eq!(forest.groups[d].targets, vec![0, 1]);
        assert!(forest.locate(forest.group_key(d).unwrap()).is_some());
        assert!(forest.locate(-1).is_none());
    }
    #[test]
    fn checking_drive_affects_only_its_marked_targets_not_ancestors_or_other_drives() {
        let a = tree("D:/xxxx", "D:/", 10);
        let b = tree("D:/yyyy", "D:/", 20);
        let c = tree("C:/xxxx", "C:/", 30);
        let trees = [&a, &b, &c];
        let f = Forest::new(&trees).unwrap();
        let mut choices: Vec<_> = trees.iter().map(|t| TreeSelection::all(t)).collect();
        let group = f
            .groups
            .iter()
            .position(|g| g.path == PathBuf::from("D:/"))
            .unwrap();
        let key = f.group_key(group).unwrap();
        let (selected, total) = f.tally(&trees, &choices, key);
        assert_eq!(total.files, 2);
        assert_eq!(total.dirs, 4); // Two target roots + their empty dirs, NOT D:\
        assert_eq!(selected.allocated, 30);
        assert_eq!(f.check_state(&trees, &choices, key), 2);
        f.check(&trees, &mut choices, key, false);
        assert_eq!(choices[0].totals(0).items(), 0);
        assert_eq!(choices[1].totals(0).items(), 0);
        assert_eq!(choices[2].totals(0).files, 1);
        f.check(&trees, &mut choices, f.entry_key(0, 0).unwrap(), true);
        assert_eq!(f.check_state(&trees, &choices, key), 1);
        assert_eq!(f.tally(&trees, &choices, key).0.allocated, 10);
        f.check(&trees, &mut choices, key, true);
        assert_eq!(f.check_state(&trees, &choices, key), 2);
    }
    #[test]
    fn collapsing_or_paging_never_changes_group_totals() {
        let a = tree("D:/deep/path/one", "D:/", 42);
        let trees = [&a];
        let f = Forest::new(&trees).unwrap();
        let choices = [TreeSelection::all(&a)];
        let key = f.roots[0];
        let expected = f.tally(&trees, &choices, key);
        let mut expanded = f.initial_expansion();
        expanded.clear();
        assert_eq!(f.tally(&trees, &choices, key), expected);
        assert_eq!(f.children(&trees, key).len(), 1);
    }
    #[test]
    fn group_never_becomes_an_entry_key() {
        let a = tree("D:/one", "D:/", 42);
        let trees = [&a];
        let f = Forest::new(&trees).unwrap();
        assert!(matches!(f.locate(f.roots[0]), Some(Location::Group(_))));
        for n in 0..a.nodes.len() as u32 {
            assert_eq!(
                f.locate(f.entry_key(0, n).unwrap()),
                Some(Location::Entry { target: 0, node: n })
            );
        }
    }
}
