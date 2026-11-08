use crate::domain::config::{Profile, ProfileId};
use std::collections::{BTreeMap, HashSet};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VisibleTreeNode {
    Folder {
        path: String,
        name: String,
        depth: usize,
        expanded: bool,
        total_profiles: usize,
    },
    Profile {
        id: ProfileId,
        name: String,
        depth: usize,
        profile_idx: usize,
    },
}

impl VisibleTreeNode {
    pub fn is_folder(&self) -> bool {
        matches!(self, VisibleTreeNode::Folder { .. })
    }

    pub fn folder_path(&self) -> Option<&str> {
        match self {
            VisibleTreeNode::Folder { path, .. } => Some(path.as_str()),
            _ => None,
        }
    }

    pub fn profile_idx(&self) -> Option<usize> {
        match self {
            VisibleTreeNode::Profile { profile_idx, .. } => Some(*profile_idx),
            _ => None,
        }
    }
}

#[derive(Default)]
struct FolderNode {
    name: String,
    full_path: String,
    subfolders: BTreeMap<String, FolderNode>,
    profile_indices: Vec<usize>,
}

impl FolderNode {
    fn new(name: String, full_path: String) -> Self {
        Self {
            name,
            full_path,
            subfolders: BTreeMap::new(),
            profile_indices: Vec::new(),
        }
    }

    fn count_total_profiles(&self) -> usize {
        let direct = self.profile_indices.len();
        let sub: usize = self
            .subfolders
            .values()
            .map(|s| s.count_total_profiles())
            .sum();
        direct + sub
    }
}

pub fn build_visible_tree(
    profiles: &[Profile],
    expanded_folders: &HashSet<String>,
    explicit_folders: &[String],
) -> Vec<VisibleTreeNode> {
    let mut root_folders: BTreeMap<String, FolderNode> = BTreeMap::new();
    let mut root_profiles: Vec<usize> = Vec::new();

    // 0. Seed explicit/empty folders
    for folder_str in explicit_folders {
        let folder_str = folder_str.trim();
        if folder_str.is_empty() {
            continue;
        }

        let segments: Vec<&str> = folder_str
            .split('/')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .collect();

        if segments.is_empty() {
            continue;
        }

        let mut current_map = &mut root_folders;
        let mut path_acc = String::new();

        for seg in segments {
            if !path_acc.is_empty() {
                path_acc.push('/');
            }
            path_acc.push_str(seg);

            let node = current_map
                .entry(seg.to_string())
                .or_insert_with(|| FolderNode::new(seg.to_string(), path_acc.clone()));

            current_map = &mut node.subfolders;
        }
    }

    for (idx, profile) in profiles.iter().enumerate() {
        let group_str = profile.group.as_deref().unwrap_or("").trim();
        if group_str.is_empty() {
            root_profiles.push(idx);
            continue;
        }

        let segments: Vec<&str> = group_str
            .split('/')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .collect();

        if segments.is_empty() {
            root_profiles.push(idx);
            continue;
        }

        let mut current_map = &mut root_folders;
        let mut path_acc = String::new();

        for (seg_idx, seg) in segments.iter().enumerate() {
            if !path_acc.is_empty() {
                path_acc.push('/');
            }
            path_acc.push_str(seg);

            let node = current_map
                .entry((*seg).to_string())
                .or_insert_with(|| FolderNode::new((*seg).to_string(), path_acc.clone()));

            if seg_idx == segments.len() - 1 {
                node.profile_indices.push(idx);
                break;
            } else {
                current_map = &mut node.subfolders;
            }
        }
    }

    let mut result = Vec::new();

    // 1. Traverse folders recursively
    for folder in root_folders.values() {
        flatten_folder(folder, 0, profiles, expanded_folders, &mut result);
    }

    // 2. Root profiles at depth 0
    for idx in root_profiles {
        result.push(VisibleTreeNode::Profile {
            id: profiles[idx].id.clone(),
            name: profiles[idx].name.clone(),
            depth: 0,
            profile_idx: idx,
        });
    }

    result
}

fn flatten_folder(
    folder: &FolderNode,
    depth: usize,
    profiles: &[Profile],
    expanded_folders: &HashSet<String>,
    out: &mut Vec<VisibleTreeNode>,
) {
    let is_expanded = expanded_folders.contains(&folder.full_path);
    let count = folder.count_total_profiles();

    out.push(VisibleTreeNode::Folder {
        path: folder.full_path.clone(),
        name: folder.name.clone(),
        depth,
        expanded: is_expanded,
        total_profiles: count,
    });

    if is_expanded {
        // Child folders
        for sub in folder.subfolders.values() {
            flatten_folder(sub, depth + 1, profiles, expanded_folders, out);
        }

        // Direct profiles in this folder
        for &idx in &folder.profile_indices {
            out.push(VisibleTreeNode::Profile {
                id: profiles[idx].id.clone(),
                name: profiles[idx].name.clone(),
                depth: depth + 1,
                profile_idx: idx,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tree_flattening_collapsed_and_expanded() {
        let profiles = vec![
            Profile::new_openconnect("DE Frankfurt", "1.1.1.1:443").with_group("BioVPN/Cisco"),
            Profile::new_openconnect("NL Amsterdam", "2.2.2.2:443").with_group("BioVPN/Cisco"),
            Profile::new_openvpn("US NewYork", "3.3.3.3:1194", None).with_group("BioVPN/OpenVPN"),
            Profile::new_openconnect("Office HQ", "4.4.4.4:443").with_group("Work"),
            Profile::new_openconnect("Standalone Root", "5.5.5.5:443"),
        ];

        // 1. All collapsed: only top-level folders and root profiles appear
        let mut expanded = HashSet::new();
        let tree1 = build_visible_tree(&profiles, &expanded, &[]);

        assert_eq!(tree1.len(), 3);
        assert_eq!(
            tree1[0],
            VisibleTreeNode::Folder {
                path: "BioVPN".into(),
                name: "BioVPN".into(),
                depth: 0,
                expanded: false,
                total_profiles: 3,
            }
        );
        assert_eq!(
            tree1[1],
            VisibleTreeNode::Folder {
                path: "Work".into(),
                name: "Work".into(),
                depth: 0,
                expanded: false,
                total_profiles: 1,
            }
        );
        assert_eq!(
            tree1[2],
            VisibleTreeNode::Profile {
                id: ProfileId("standalone-root".into()),
                name: "Standalone Root".into(),
                depth: 0,
                profile_idx: 4,
            }
        );

        // 2. Expand BioVPN
        expanded.insert("BioVPN".into());
        let tree2 = build_visible_tree(&profiles, &expanded, &[]);
        // Visible: BioVPN (depth 0), BioVPN/Cisco (depth 1), BioVPN/OpenVPN (depth 1), Work (depth 0), Standalone (depth 0)
        assert_eq!(tree2.len(), 5);
        assert_eq!(
            tree2[1],
            VisibleTreeNode::Folder {
                path: "BioVPN/Cisco".into(),
                name: "Cisco".into(),
                depth: 1,
                expanded: false,
                total_profiles: 2,
            }
        );
        assert_eq!(
            tree2[2],
            VisibleTreeNode::Folder {
                path: "BioVPN/OpenVPN".into(),
                name: "OpenVPN".into(),
                depth: 1,
                expanded: false,
                total_profiles: 1,
            }
        );

        // 3. Expand BioVPN/Cisco
        expanded.insert("BioVPN/Cisco".into());
        let tree3 = build_visible_tree(&profiles, &expanded, &[]);
        // Visible: BioVPN, Cisco, DE Frankfurt (depth 2), NL Amsterdam (depth 2), OpenVPN, Work, Standalone
        assert_eq!(tree3.len(), 7);
        assert_eq!(
            tree3[2],
            VisibleTreeNode::Profile {
                id: ProfileId("de-frankfurt".into()),
                name: "DE Frankfurt".into(),
                depth: 2,
                profile_idx: 0,
            }
        );
        assert_eq!(
            tree3[3],
            VisibleTreeNode::Profile {
                id: ProfileId("nl-amsterdam".into()),
                name: "NL Amsterdam".into(),
                depth: 2,
                profile_idx: 1,
            }
        );
    }

    #[test]
    fn test_tree_with_empty_explicit_folders() {
        let profiles =
            vec![Profile::new_openconnect("DE Munich", "1.1.1.1:443").with_group("Work/Europe")];

        let explicit_folders = vec![
            "EmptyTopLevel".to_string(),
            "Work/Asia".to_string(), // Empty subfolder of Work
        ];

        let mut expanded = HashSet::new();
        // Top level when collapsed: EmptyTopLevel (count 0), Work (count 1)
        let tree_collapsed = build_visible_tree(&profiles, &expanded, &explicit_folders);
        assert_eq!(tree_collapsed.len(), 2);
        assert_eq!(
            tree_collapsed[0],
            VisibleTreeNode::Folder {
                path: "EmptyTopLevel".into(),
                name: "EmptyTopLevel".into(),
                depth: 0,
                expanded: false,
                total_profiles: 0,
            }
        );
        assert_eq!(
            tree_collapsed[1],
            VisibleTreeNode::Folder {
                path: "Work".into(),
                name: "Work".into(),
                depth: 0,
                expanded: false,
                total_profiles: 1,
            }
        );

        // Expand Work -> Shows Empty subfolder Work/Asia (count 0) and Work/Europe (count 1)
        expanded.insert("Work".into());
        let tree_expanded = build_visible_tree(&profiles, &expanded, &explicit_folders);
        assert_eq!(tree_expanded.len(), 4);
        assert_eq!(tree_expanded[1].folder_path(), Some("Work"));
        assert_eq!(
            tree_expanded[2],
            VisibleTreeNode::Folder {
                path: "Work/Asia".into(),
                name: "Asia".into(),
                depth: 1,
                expanded: false,
                total_profiles: 0,
            }
        );
        assert_eq!(
            tree_expanded[3],
            VisibleTreeNode::Folder {
                path: "Work/Europe".into(),
                name: "Europe".into(),
                depth: 1,
                expanded: false,
                total_profiles: 1,
            }
        );
    }
}
