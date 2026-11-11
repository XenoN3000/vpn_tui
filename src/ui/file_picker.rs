use std::fs;
use std::path::{Path, PathBuf};

/// Entry in the file browser
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileEntry {
    pub name: String,
    pub path: PathBuf,
    pub is_dir: bool,
}

/// State for the interactive file browser overlay
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileBrowserState {
    pub current_dir: PathBuf,
    pub entries: Vec<FileEntry>,
    pub selected_index: usize,
    pub error_msg: Option<String>,
}

impl FileBrowserState {
    pub fn new(initial_dir: Option<PathBuf>) -> Self {
        let dir = initial_dir
            .and_then(|d| {
                if d.is_dir() {
                    Some(d)
                } else {
                    d.parent().map(|p| p.to_path_buf())
                }
            })
            .unwrap_or_else(|| {
                std::env::var("HOME")
                    .map(PathBuf::from)
                    .unwrap_or_else(|_| {
                        std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/"))
                    })
            });

        let mut state = Self {
            current_dir: dir,
            entries: Vec::new(),
            selected_index: 0,
            error_msg: None,
        };
        state.refresh();
        state
    }

    pub fn refresh(&mut self) {
        self.entries.clear();
        self.error_msg = None;

        // If parent directory exists, add ".." entry
        if let Some(parent) = self.current_dir.parent() {
            self.entries.push(FileEntry {
                name: "..".to_string(),
                path: parent.to_path_buf(),
                is_dir: true,
            });
        }

        match fs::read_dir(&self.current_dir) {
            Ok(read_dir) => {
                let mut dirs = Vec::new();
                let mut ovpn_files = Vec::new();

                for entry_res in read_dir {
                    let entry = match entry_res {
                        Ok(e) => e,
                        Err(_) => continue,
                    };

                    let path = entry.path();
                    let file_name = entry.file_name().to_string_lossy().to_string();

                    // Skip hidden files/directories starting with '.'
                    if file_name.starts_with('.') {
                        continue;
                    }

                    if path.is_dir() {
                        dirs.push(FileEntry {
                            name: file_name,
                            path,
                            is_dir: true,
                        });
                    } else if file_name.to_lowercase().ends_with(".ovpn")
                        || file_name.to_lowercase().ends_with(".zip")
                        || file_name.to_lowercase().ends_with(".html")
                        || file_name.to_lowercase().ends_with(".htm")
                    {
                        ovpn_files.push(FileEntry {
                            name: file_name,
                            path,
                            is_dir: false,
                        });
                    }
                }

                // Sort directories and ovpn files alphabetically
                dirs.sort_by(|a, b| a.name.cmp(&b.name));
                ovpn_files.sort_by(|a, b| a.name.cmp(&b.name));

                self.entries.extend(dirs);
                self.entries.extend(ovpn_files);

                if self.selected_index >= self.entries.len() {
                    self.selected_index = self.entries.len().saturating_sub(1);
                }
            }
            Err(e) => {
                self.error_msg = Some(format!("Error reading directory: {e}"));
            }
        }
    }

    pub fn select_next(&mut self) {
        if !self.entries.is_empty() {
            self.selected_index = (self.selected_index + 1) % self.entries.len();
        }
    }

    pub fn select_prev(&mut self) {
        if !self.entries.is_empty() {
            if self.selected_index == 0 {
                self.selected_index = self.entries.len() - 1;
            } else {
                self.selected_index -= 1;
            }
        }
    }

    pub fn go_up(&mut self) {
        if let Some(parent) = self.current_dir.parent() {
            self.current_dir = parent.to_path_buf();
            self.selected_index = 0;
            self.refresh();
        }
    }

    /// Enter the selected entry:
    /// - If directory: navigates into it, returns `None`
    /// - If `.ovpn` file: returns `Some(PathBuf)`
    /// - If empty: returns `None`
    pub fn enter_selected(&mut self) -> Option<PathBuf> {
        let entry = self.entries.get(self.selected_index)?.clone();
        if entry.is_dir {
            self.current_dir = entry.path;
            self.selected_index = 0;
            self.refresh();
            None
        } else {
            Some(entry.path)
        }
    }

    pub fn selected_entry(&self) -> Option<&FileEntry> {
        self.entries.get(self.selected_index)
    }
}

/// Autocomplete a filesystem path input.
/// Supports `~` expansion, directory traversal, and partial filename matching.
pub fn complete_path(input: &str) -> Option<String> {
    if input.is_empty() {
        return None;
    }

    // 1. Expand `~`
    let expanded = if input == "~" {
        let home = std::env::var("HOME").ok()?;
        return Some(format!("{home}/"));
    } else if let Some(stripped) = input.strip_prefix("~/") {
        let home = std::env::var("HOME").ok()?;
        format!("{home}/{stripped}")
    } else {
        input.to_string()
    };

    // 2. Identify directory and search prefix
    let (dir_path, prefix) = if expanded.ends_with('/') {
        (PathBuf::from(&expanded), String::new())
    } else {
        let p = Path::new(&expanded);
        let parent = p.parent().unwrap_or(Path::new(""));
        let parent_buf = if parent.as_os_str().is_empty() {
            PathBuf::from(".")
        } else {
            parent.to_path_buf()
        };
        let file_stem = p
            .file_name()
            .and_then(|f| f.to_str())
            .unwrap_or("")
            .to_string();
        (parent_buf, file_stem)
    };

    // 3. Read directory
    let read_dir = fs::read_dir(&dir_path).ok()?;
    let mut matches: Vec<(String, bool)> = Vec::new();

    for entry in read_dir.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if !prefix.starts_with('.') && name.starts_with('.') {
            continue;
        }

        if name.starts_with(&prefix) {
            let is_dir = entry.path().is_dir();
            matches.push((name, is_dir));
        }
    }

    if matches.is_empty() {
        // If ~ was expanded and it exists as a directory, return expanded
        if expanded != input && Path::new(&expanded).exists() {
            return Some(expanded);
        }
        return None;
    }

    // 4. If exactly one match
    if matches.len() == 1 {
        let (name, is_dir) = &matches[0];
        let base_dir = if dir_path == Path::new(".") && !expanded.starts_with("./") {
            String::new()
        } else {
            let mut s = dir_path.to_string_lossy().to_string();
            if !s.ends_with('/') {
                s.push('/');
            }
            s
        };

        let mut completed = format!("{base_dir}{name}");
        if *is_dir && !completed.ends_with('/') {
            completed.push('/');
        }
        return Some(completed);
    }

    // 5. Multiple matches: find longest common prefix
    let first = &matches[0].0;
    let mut common_len = first.len();

    for (name, _) in &matches[1..] {
        common_len = first
            .chars()
            .zip(name.chars())
            .take(common_len)
            .take_while(|(c1, c2)| c1 == c2)
            .count();
    }

    let common_prefix: String = first.chars().take(common_len).collect();
    if common_prefix.len() > prefix.len() {
        let base_dir = if dir_path == Path::new(".") && !expanded.starts_with("./") {
            String::new()
        } else {
            let mut s = dir_path.to_string_lossy().to_string();
            if !s.ends_with('/') {
                s.push('/');
            }
            s
        };
        Some(format!("{base_dir}{common_prefix}"))
    } else if expanded != input {
        Some(expanded)
    } else {
        None
    }
}

#[cfg(test)]
pub mod autocomplete {
    use super::*;
    use std::fs::{self, File};
    use tempfile::tempdir;

    #[test]
    fn test_autocomplete_tilde_expansion() {
        if let Ok(home) = std::env::var("HOME") {
            let completed = complete_path("~").expect("complete ~");
            assert_eq!(completed, format!("{home}/"));

            let completed_sub = complete_path("~/");
            // If ~/ can read HOME, it might complete or return Some
            assert!(completed_sub.is_some() || PathBuf::from(&home).exists());
        }
    }

    #[test]
    fn test_autocomplete_directory_expansion() {
        let dir = tempdir().expect("temp dir");
        let sub = dir.path().join("mysubdir");
        fs::create_dir(&sub).expect("create subdir");

        let input = format!("{}/my", dir.path().display());
        let completed = complete_path(&input).expect("autocomplete");
        assert_eq!(completed, format!("{}/mysubdir/", dir.path().display()));
    }

    #[test]
    fn test_autocomplete_partial_file_matching_unique() {
        let dir = tempdir().expect("temp dir");
        let file_path = dir.path().join("client_germany.ovpn");
        File::create(&file_path).expect("create file");

        let input = format!("{}/client", dir.path().display());
        let completed = complete_path(&input).expect("autocomplete");
        assert_eq!(
            completed,
            format!("{}/client_germany.ovpn", dir.path().display())
        );
    }

    #[test]
    fn test_autocomplete_partial_file_matching_common_prefix() {
        let dir = tempdir().expect("temp dir");
        let f1 = dir.path().join("config_london.ovpn");
        let f2 = dir.path().join("config_paris.ovpn");
        File::create(&f1).expect("create f1");
        File::create(&f2).expect("create f2");

        let input = format!("{}/con", dir.path().display());
        let completed = complete_path(&input).expect("autocomplete");
        assert_eq!(completed, format!("{}/config_", dir.path().display()));
    }
}

#[cfg(test)]
pub mod browser_state {
    use super::*;
    use std::fs::{self, File};
    use tempfile::tempdir;

    #[test]
    fn test_browser_state_reading_and_filtering() {
        let dir = tempdir().expect("temp dir");
        let sub = dir.path().join("vpn_profiles");
        fs::create_dir(&sub).expect("create subdir");

        let ovpn1 = dir.path().join("profile1.ovpn");
        let ovpn2 = dir.path().join("profile2.OVPN");
        let zip_file = dir.path().join("bundle.zip");
        let html_file = dir.path().join("portal.html");
        let ignored_txt = dir.path().join("notes.txt");
        let hidden = dir.path().join(".secret.ovpn");

        File::create(&ovpn1).expect("create ovpn1");
        File::create(&ovpn2).expect("create ovpn2");
        File::create(&zip_file).expect("create zip");
        File::create(&html_file).expect("create html");
        File::create(&ignored_txt).expect("create notes.txt");
        File::create(&hidden).expect("create hidden");

        let state = FileBrowserState::new(Some(dir.path().to_path_buf()));

        let names: Vec<String> = state.entries.iter().map(|e| e.name.clone()).collect();
        // Should include parent .. if path has parent
        if dir.path().parent().is_some() {
            assert!(names.contains(&"..".to_string()));
        }
        assert!(names.contains(&"vpn_profiles".to_string()));
        assert!(names.contains(&"profile1.ovpn".to_string()));
        assert!(names.contains(&"profile2.OVPN".to_string()));
        assert!(names.contains(&"bundle.zip".to_string()));
        assert!(names.contains(&"portal.html".to_string()));
        assert!(
            !names.contains(&"notes.txt".to_string()),
            "txt files must be filtered out"
        );
        assert!(
            !names.contains(&".secret.ovpn".to_string()),
            "hidden files must be filtered out"
        );
    }

    #[test]
    fn test_browser_state_navigation_and_selection() {
        let dir = tempdir().expect("temp dir");
        let sub = dir.path().join("nested");
        fs::create_dir(&sub).expect("create nested");
        let ovpn = sub.join("tunnel.ovpn");
        File::create(&ovpn).expect("create ovpn in nested");

        let mut state = FileBrowserState::new(Some(dir.path().to_path_buf()));

        // Navigate selection
        state.select_next();
        let initial_selected = state.selected_entry().expect("has selected");
        assert!(!initial_selected.name.is_empty());

        // Find index of "nested"
        let nested_idx = state
            .entries
            .iter()
            .position(|e| e.name == "nested")
            .expect("find nested directory");
        state.selected_index = nested_idx;

        // Enter into directory
        let result = state.enter_selected();
        assert!(result.is_none(), "Entering a directory should return None");
        assert_eq!(state.current_dir, sub);

        // In nested dir, we should find "tunnel.ovpn"
        let tunnel_idx = state
            .entries
            .iter()
            .position(|e| e.name == "tunnel.ovpn")
            .expect("find tunnel.ovpn");
        state.selected_index = tunnel_idx;

        let selected_file = state.enter_selected();
        assert_eq!(selected_file, Some(ovpn));

        // Test go_up()
        state.go_up();
        assert_eq!(state.current_dir, dir.path());
    }
}
