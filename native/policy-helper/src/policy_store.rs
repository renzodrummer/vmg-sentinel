use crate::policy::{parse_document, PolicyDocument, PolicyError};
use crate::ttl::format_rfc3339;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use time::OffsetDateTime;

pub struct PolicyStore {
    dir: PathBuf,
}

impl PolicyStore {
    pub fn new(dir: PathBuf) -> Self {
        Self { dir }
    }

    fn last_good_path(&self) -> PathBuf {
        self.dir.join("last-good.json")
    }

    pub fn tamper_log_path(&self) -> PathBuf {
        self.dir.join("tamper.log")
    }

    pub fn ensure_dir(&self) -> io::Result<()> {
        fs::create_dir_all(&self.dir)
    }

    pub fn load_last_good(&self) -> Result<Option<PolicyDocument>, PolicyError> {
        let path = self.last_good_path();
        if !path.exists() {
            return Ok(None);
        }
        let raw = fs::read_to_string(path).map_err(|_| PolicyError::Invalid)?;
        Ok(Some(parse_document(&raw)?))
    }

    pub fn save_last_good(&self, doc: &PolicyDocument) -> io::Result<()> {
        self.ensure_dir()?;
        let raw = serde_json::to_string(doc)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        let tmp = self.dir.join("last-good.json.tmp");
        fs::write(&tmp, raw)?;
        fs::rename(tmp, self.last_good_path())
    }

    pub fn append_tamper(&self, kind: &str, detail: &str) -> io::Result<()> {
        self.ensure_dir()?;
        let line = format!(
            "{}\tkind={}\tdetail={}\n",
            format_rfc3339(OffsetDateTime::now_utc()),
            kind.replace(['\t', '\n'], " "),
            detail.replace(['\t', '\n'], " ")
        );
        use std::io::Write;
        let mut file = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.tamper_log_path())?;
        file.write_all(line.as_bytes())
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }
}
