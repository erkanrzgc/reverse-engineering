//! Atomic output helpers.

use anyhow::{Context, Result};
use std::io::Write;
use std::path::Path;

/// Atomically makes `contents` visible at `path`, replacing an existing file.
///
/// The temporary file is created beside the destination so the final persist
/// stays on one filesystem. Its contents are synced before replacement, and
/// dropping it after any failed step removes it. This does not sync the parent
/// directory, so it prevents readers from observing partial contents but does
/// not promise that the directory entry survives sudden power loss.
pub fn atomic_write(path: &Path, contents: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut temporary = tempfile::NamedTempFile::new_in(parent)
        .with_context(|| format!("failed to create temporary output for {}", path.display()))?;

    temporary
        .write_all(contents)
        .with_context(|| format!("failed to write temporary output for {}", path.display()))?;
    temporary
        .flush()
        .with_context(|| format!("failed to flush temporary output for {}", path.display()))?;
    temporary
        .as_file()
        .sync_all()
        .with_context(|| format!("failed to sync temporary output for {}", path.display()))?;
    temporary
        .persist(path)
        .with_context(|| format!("failed to atomically replace {}", path.display()))?;

    Ok(())
}
