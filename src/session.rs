use std::path::{Path, PathBuf};

pub const DEFAULT_SESSION_NAME: &str = "default";
pub const RECORDINGS_DB_FILENAME: &str = "recordings.db";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionNameError {
    reason: String,
}

impl SessionNameError {
    fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
        }
    }
}

impl std::fmt::Display for SessionNameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.reason)
    }
}

impl std::error::Error for SessionNameError {}

pub fn validate_session_name(name: &str) -> Result<(), SessionNameError> {
    if name.trim().is_empty() {
        return Err(SessionNameError::new("session name cannot be empty"));
    }
    if name != name.trim() {
        return Err(SessionNameError::new(
            "session name cannot have leading or trailing whitespace",
        ));
    }
    if name.contains('/') || name.contains('\\') {
        return Err(SessionNameError::new(
            "session name cannot contain path separators",
        ));
    }
    if name == "." || name == ".." {
        return Err(SessionNameError::new("session name cannot be `.` or `..`"));
    }

    Ok(())
}

pub fn resolve_session_dir(
    base_path: &Path,
    session_name: &str,
) -> Result<PathBuf, SessionNameError> {
    validate_session_name(session_name)?;
    Ok(base_path.join(session_name))
}

pub fn resolve_session_db_path(
    base_path: &Path,
    session_name: &str,
) -> Result<PathBuf, SessionNameError> {
    Ok(resolve_session_dir(base_path, session_name)?.join(RECORDINGS_DB_FILENAME))
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::{resolve_session_db_path, validate_session_name};

    #[test]
    fn resolve_session_db_path_uses_canonical_layout() {
        let resolved = resolve_session_db_path(Path::new("/tmp/sessions"), "staging").unwrap();
        assert_eq!(resolved, Path::new("/tmp/sessions/staging/recordings.db"));
    }

    #[test]
    fn validate_session_name_rejects_unsafe_names() {
        let cases = [
            "", " default", "default ", "../prod", "a/b", r"a\b", ".", "..",
        ];
        for case in cases {
            assert!(
                validate_session_name(case).is_err(),
                "case `{case}` should fail"
            );
        }
    }
}
