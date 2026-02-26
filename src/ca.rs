use std::{
    collections::HashMap,
    env, fs,
    io::{ErrorKind, Write},
    path::{Path, PathBuf},
    process::{Command, Output},
    sync::{Arc, Mutex},
};

use anyhow::{Context, bail};
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair,
    KeyUsagePurpose,
};
use x509_parser::{parse_x509_certificate, pem::parse_x509_pem};

pub const DEFAULT_CA_SUBDIR: &str = ".replayproxy/ca";
pub const CA_CERT_FILE_NAME: &str = "cert.pem";
pub const CA_KEY_FILE_NAME: &str = "key.pem";
pub const DEFAULT_EXPORT_CERT_FILE_NAME: &str = "replayproxy-ca.pem";

const ROOT_CA_COMMON_NAME: &str = "replayproxy Local Root CA";
const DIR_MODE_RESTRICTED: u32 = 0o700;
const FILE_MODE_RESTRICTED: u32 = 0o600;
const FILE_MODE_READABLE: u32 = 0o644;
const LINUX_SYSTEM_CERT_INSTALL_PATH: &str = "/usr/local/share/ca-certificates/replayproxy-ca.crt";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaMaterialPaths {
    pub ca_dir: PathBuf,
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
}

impl CaMaterialPaths {
    fn from_dir(ca_dir: &Path) -> Self {
        Self {
            ca_dir: ca_dir.to_path_buf(),
            cert_path: ca_dir.join(CA_CERT_FILE_NAME),
            key_path: ca_dir.join(CA_KEY_FILE_NAME),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CaInstallResult {
    Installed {
        method: &'static str,
        details: String,
    },
    Manual {
        details: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeafCertMaterial {
    pub hostname: String,
    pub cert_pem: String,
    pub key_pem: String,
}

#[derive(Debug)]
pub struct LeafCertGenerator {
    issuer: Issuer<'static, KeyPair>,
    cache: Mutex<HashMap<String, Arc<LeafCertMaterial>>>,
}

impl LeafCertGenerator {
    pub fn from_ca_dir(ca_dir: &Path) -> anyhow::Result<Self> {
        let paths = ca_material_paths(ca_dir);
        Self::from_ca_files(&paths.cert_path, &paths.key_path)
    }

    pub fn from_ca_files(cert_path: &Path, key_path: &Path) -> anyhow::Result<Self> {
        validate_ca_material(cert_path, key_path)?;

        let ca_cert_pem = fs::read_to_string(cert_path)
            .with_context(|| format!("read CA certificate {}", cert_path.display()))?;
        let ca_key_pem = fs::read_to_string(key_path)
            .with_context(|| format!("read CA private key {}", key_path.display()))?;
        Self::from_ca_pem(&ca_cert_pem, &ca_key_pem)
    }

    pub fn from_ca_pem(ca_cert_pem: &str, ca_key_pem: &str) -> anyhow::Result<Self> {
        let key_pair =
            KeyPair::from_pem(ca_key_pem).context("parse CA private key for leaf issuance")?;
        let issuer = Issuer::from_ca_cert_pem(ca_cert_pem, key_pair)
            .context("parse CA certificate for leaf issuance")?;

        Ok(Self {
            issuer,
            cache: Mutex::new(HashMap::new()),
        })
    }

    pub fn issue_for_host(&self, hostname: &str) -> anyhow::Result<Arc<LeafCertMaterial>> {
        let normalized_hostname = normalize_leaf_hostname(hostname)?;

        let mut cache = self
            .cache
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(existing) = cache.get(&normalized_hostname) {
            return Ok(Arc::clone(existing));
        }

        let mut params =
            CertificateParams::new(vec![normalized_hostname.clone()]).with_context(|| {
                format!("initialize leaf certificate parameters for `{normalized_hostname}`")
            })?;
        params
            .distinguished_name
            .push(DnType::CommonName, normalized_hostname.clone());
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        params.is_ca = IsCa::NoCa;
        params.use_authority_key_identifier_extension = true;

        let leaf_key = KeyPair::generate()
            .with_context(|| format!("generate leaf key for `{normalized_hostname}`"))?;
        let cert = params
            .signed_by(&leaf_key, &self.issuer)
            .with_context(|| format!("sign leaf certificate for `{normalized_hostname}`"))?;

        let material = Arc::new(LeafCertMaterial {
            hostname: normalized_hostname.clone(),
            cert_pem: cert.pem(),
            key_pem: leaf_key.serialize_pem(),
        });
        cache.insert(normalized_hostname, Arc::clone(&material));
        Ok(material)
    }
}

fn normalize_leaf_hostname(hostname: &str) -> anyhow::Result<String> {
    let hostname = hostname.trim();
    if hostname.is_empty() {
        bail!("leaf certificate hostname must not be empty");
    }

    let mut normalized = if hostname.starts_with('[') && hostname.ends_with(']') {
        hostname[1..hostname.len() - 1].to_owned()
    } else {
        hostname.to_owned()
    };
    if let Some(stripped) = normalized.strip_suffix('.')
        && !stripped.is_empty()
    {
        normalized = stripped.to_owned();
    }
    if normalized.is_empty() {
        bail!("leaf certificate hostname must not be empty");
    }

    Ok(normalized.to_ascii_lowercase())
}

pub fn default_ca_dir() -> anyhow::Result<PathBuf> {
    let Some(home) = env::var_os("HOME") else {
        bail!("cannot resolve CA directory: HOME is not set");
    };
    Ok(default_ca_dir_from_home(Path::new(&home)))
}

pub fn resolve_ca_dir(ca_dir_override: Option<&Path>) -> anyhow::Result<PathBuf> {
    match ca_dir_override {
        Some(path) => Ok(path.to_path_buf()),
        None => default_ca_dir(),
    }
}

pub fn ca_material_paths(ca_dir: &Path) -> CaMaterialPaths {
    CaMaterialPaths::from_dir(ca_dir)
}

pub fn generate_ca(ca_dir: &Path, force: bool) -> anyhow::Result<CaMaterialPaths> {
    let paths = ca_material_paths(ca_dir);

    fs::create_dir_all(ca_dir)
        .with_context(|| format!("create CA directory {}", ca_dir.display()))?;
    set_dir_permissions(ca_dir, DIR_MODE_RESTRICTED)?;

    if !force && (paths.cert_path.exists() || paths.key_path.exists()) {
        bail!(
            "CA material already exists at {}; pass `--force` to overwrite",
            ca_dir.display()
        );
    }

    let mut params =
        CertificateParams::new(Vec::new()).context("initialize root CA certificate parameters")?;
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params
        .distinguished_name
        .push(DnType::CommonName, ROOT_CA_COMMON_NAME);
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
    ];

    let key_pair = KeyPair::generate().context("generate root CA private key")?;
    let cert = params
        .self_signed(&key_pair)
        .context("self-sign root CA certificate")?;

    write_file_with_permissions(
        &paths.cert_path,
        cert.pem().as_bytes(),
        force,
        FILE_MODE_RESTRICTED,
    )?;
    write_file_with_permissions(
        &paths.key_path,
        key_pair.serialize_pem().as_bytes(),
        force,
        FILE_MODE_RESTRICTED,
    )?;

    Ok(paths)
}

pub fn validate_ca_material(cert_path: &Path, key_path: &Path) -> anyhow::Result<()> {
    let cert_pem = fs::read(cert_path)
        .with_context(|| format!("read CA certificate {}", cert_path.display()))?;
    let key_pem = fs::read_to_string(key_path)
        .with_context(|| format!("read CA private key {}", key_path.display()))?;

    let key_pair = KeyPair::from_pem(&key_pem)
        .with_context(|| format!("parse CA private key PEM {}", key_path.display()))?;

    let (_, pem_block) = parse_x509_pem(&cert_pem).map_err(|err| {
        anyhow::anyhow!("parse CA certificate PEM {}: {err}", cert_path.display())
    })?;
    if pem_block.label != "CERTIFICATE" {
        bail!(
            "parse CA certificate PEM {}: expected CERTIFICATE block, got {}",
            cert_path.display(),
            pem_block.label
        );
    }

    let (_, certificate) = parse_x509_certificate(&pem_block.contents).map_err(|err| {
        anyhow::anyhow!(
            "parse CA certificate DER payload {}: {err}",
            cert_path.display()
        )
    })?;

    let cert_public_key = certificate
        .tbs_certificate
        .subject_pki
        .subject_public_key
        .data
        .as_ref();
    let key_public_key = key_pair.public_key_raw();
    if cert_public_key != key_public_key {
        bail!(
            "CA certificate {} and private key {} do not match",
            cert_path.display(),
            key_path.display()
        );
    }

    Ok(())
}

pub fn export_ca_cert(ca_dir: &Path, out_path: &Path, force: bool) -> anyhow::Result<PathBuf> {
    let paths = ca_material_paths(ca_dir);
    if !paths.cert_path.exists() {
        bail!(
            "CA certificate not found at {}; run `replayproxy ca generate` first",
            paths.cert_path.display()
        );
    }

    let cert_pem = fs::read(&paths.cert_path)
        .with_context(|| format!("read CA certificate {}", paths.cert_path.display()))?;
    write_file_with_permissions(out_path, &cert_pem, force, FILE_MODE_READABLE)?;

    Ok(out_path.to_path_buf())
}

pub fn install_ca_cert(ca_dir: &Path) -> anyhow::Result<CaInstallResult> {
    let paths = ca_material_paths(ca_dir);
    ensure_ca_certificate_exists(&paths)?;

    #[cfg(target_os = "macos")]
    {
        install_ca_macos(&paths.cert_path)
    }

    #[cfg(target_os = "linux")]
    {
        install_ca_linux(&paths.cert_path)
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let details = format!(
            "automatic CA install is not implemented for `{}`. Export or install manually from {}",
            env::consts::OS,
            paths.cert_path.display()
        );
        Ok(CaInstallResult::Manual { details })
    }
}

fn ensure_ca_certificate_exists(paths: &CaMaterialPaths) -> anyhow::Result<()> {
    if !paths.cert_path.exists() {
        bail!(
            "CA certificate not found at {}; run `replayproxy ca generate` first",
            paths.cert_path.display()
        );
    }
    Ok(())
}

fn default_ca_dir_from_home(home: &Path) -> PathBuf {
    home.join(DEFAULT_CA_SUBDIR)
}

fn write_file_with_permissions(
    path: &Path,
    contents: &[u8],
    force: bool,
    mode: u32,
) -> anyhow::Result<()> {
    if force && path.exists() {
        fs::remove_file(path)
            .with_context(|| format!("remove existing file {}", path.display()))?;
    }

    if path.exists() {
        bail!(
            "file {} already exists; pass `--force` to overwrite",
            path.display()
        );
    }

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create parent directory {}", parent.display()))?;
    }

    let mut file = create_file_with_mode(path, mode)?;
    file.write_all(contents)
        .with_context(|| format!("write file {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("sync file {}", path.display()))?;
    Ok(())
}

fn create_file_with_mode(path: &Path, mode: u32) -> anyhow::Result<fs::File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        let mut opts = fs::OpenOptions::new();
        opts.create_new(true).write(true).mode(mode);
        opts.open(path)
            .with_context(|| format!("create file {}", path.display()))
    }

    #[cfg(not(unix))]
    {
        let mut opts = fs::OpenOptions::new();
        opts.create_new(true).write(true);
        let file = opts
            .open(path)
            .with_context(|| format!("create file {}", path.display()))?;
        let mut permissions = file.metadata()?.permissions();
        permissions.set_readonly(false);
        file.set_permissions(permissions)?;
        Ok(file)
    }
}

fn set_dir_permissions(path: &Path, mode: u32) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        fs::set_permissions(path, fs::Permissions::from_mode(mode))
            .with_context(|| format!("set permissions on {}", path.display()))?;
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn install_ca_macos(cert_path: &Path) -> anyhow::Result<CaInstallResult> {
    let command = format!(
        "security add-trusted-cert -d -r trustRoot -k ~/Library/Keychains/login.keychain-db {}",
        cert_path.display()
    );
    if !command_exists("security") {
        return Ok(CaInstallResult::Manual {
            details: format!("`security` command not found. Run manually:\n{command}"),
        });
    }

    let Some(home) = env::var_os("HOME") else {
        return Ok(CaInstallResult::Manual {
            details: format!("HOME is not set. Run manually:\n{command}"),
        });
    };
    let keychain_path = Path::new(&home).join("Library/Keychains/login.keychain-db");

    let output = Command::new("security")
        .arg("add-trusted-cert")
        .arg("-d")
        .arg("-r")
        .arg("trustRoot")
        .arg("-k")
        .arg(&keychain_path)
        .arg(cert_path)
        .output()
        .context("run `security add-trusted-cert`")?;

    if output.status.success() {
        return Ok(CaInstallResult::Installed {
            method: "security",
            details: format!(
                "installed CA into login keychain using `security` from {}",
                cert_path.display()
            ),
        });
    }

    Ok(CaInstallResult::Manual {
        details: format!(
            "`security add-trusted-cert` failed ({}). Run manually:\n{command}",
            command_failure_summary(&output)
        ),
    })
}

#[cfg(target_os = "linux")]
fn install_ca_linux(cert_path: &Path) -> anyhow::Result<CaInstallResult> {
    let mut failures = Vec::new();

    if command_exists("trust") {
        let output = Command::new("trust")
            .arg("anchor")
            .arg(cert_path)
            .output()
            .context("run `trust anchor`")?;
        if output.status.success() {
            return Ok(CaInstallResult::Installed {
                method: "trust",
                details: format!(
                    "installed CA with `trust anchor` from {}",
                    cert_path.display()
                ),
            });
        }
        failures.push(format!(
            "`trust anchor` failed ({})",
            command_failure_summary(&output)
        ));
    } else {
        failures.push("`trust` command not found".to_owned());
    }

    if command_exists("update-ca-certificates") {
        let target_path = Path::new(LINUX_SYSTEM_CERT_INSTALL_PATH);
        match fs::copy(cert_path, target_path) {
            Ok(_) => {}
            Err(err) if err.kind() == ErrorKind::PermissionDenied => {
                failures.push(format!(
                    "permission denied writing {}",
                    target_path.display()
                ));
                return Ok(CaInstallResult::Manual {
                    details: format!(
                        "automatic install requires elevated permissions: {}.\n{}",
                        failures.join("; "),
                        linux_manual_install_instructions(cert_path)
                    ),
                });
            }
            Err(err) => {
                failures.push(format!("copy to {} failed: {err}", target_path.display()));
            }
        }

        let output = Command::new("update-ca-certificates")
            .output()
            .context("run `update-ca-certificates`")?;
        if output.status.success() {
            return Ok(CaInstallResult::Installed {
                method: "update-ca-certificates",
                details: format!(
                    "installed CA to {} and refreshed trust store",
                    target_path.display()
                ),
            });
        }
        failures.push(format!(
            "`update-ca-certificates` failed ({})",
            command_failure_summary(&output)
        ));
    } else {
        failures.push("`update-ca-certificates` command not found".to_owned());
    }

    Ok(CaInstallResult::Manual {
        details: format!(
            "automatic Linux install was not successful: {}.\n{}",
            failures.join("; "),
            linux_manual_install_instructions(cert_path)
        ),
    })
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn command_exists(_name: &str) -> bool {
    false
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn command_exists(name: &str) -> bool {
    let Some(path) = env::var_os("PATH") else {
        return false;
    };
    env::split_paths(&path).any(|dir| dir.join(name).is_file())
}

#[cfg(target_os = "linux")]
fn linux_manual_install_instructions(cert_path: &Path) -> String {
    format!(
        "Manual install options:\n- Debian/Ubuntu: sudo cp {} {} && sudo update-ca-certificates\n- Fedora/RHEL: sudo trust anchor {}",
        cert_path.display(),
        LINUX_SYSTEM_CERT_INSTALL_PATH,
        cert_path.display()
    )
}

fn command_failure_summary(output: &Output) -> String {
    let stderr = trim_bytes(output.stderr.as_slice());
    if !stderr.is_empty() {
        return stderr;
    }
    let stdout = trim_bytes(output.stdout.as_slice());
    if !stdout.is_empty() {
        return stdout;
    }
    match output.status.code() {
        Some(code) => format!("exit code {code}"),
        None => "terminated by signal".to_owned(),
    }
}

fn trim_bytes(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).trim().to_owned()
}

#[cfg(test)]
mod tests {
    use std::{fs, path::Path, sync::Arc};

    use super::{
        DEFAULT_CA_SUBDIR, LeafCertGenerator, default_ca_dir_from_home, export_ca_cert,
        generate_ca, linux_manual_install_instructions, validate_ca_material,
    };
    use tempfile::tempdir;
    use x509_parser::extensions::GeneralName;

    #[test]
    fn default_ca_dir_from_home_appends_expected_subdir() {
        let home = Path::new("/tmp/home-test");
        assert_eq!(default_ca_dir_from_home(home), home.join(DEFAULT_CA_SUBDIR));
    }

    #[test]
    fn generate_ca_creates_cert_and_key_files() {
        let temp_dir = tempdir().expect("tempdir should be created");
        let ca_dir = temp_dir.path().join("ca");

        let paths = generate_ca(&ca_dir, false).expect("CA generation should succeed");

        assert!(paths.cert_path.exists(), "cert should exist");
        assert!(paths.key_path.exists(), "key should exist");
        let cert_pem = fs::read_to_string(paths.cert_path).expect("cert should be readable");
        assert!(
            cert_pem.contains("BEGIN CERTIFICATE"),
            "cert should be PEM encoded"
        );
        let key_pem = fs::read_to_string(paths.key_path).expect("key should be readable");
        assert!(
            key_pem.contains("BEGIN PRIVATE KEY"),
            "key should be PEM encoded"
        );
    }

    #[test]
    fn generate_ca_requires_force_when_files_already_exist() {
        let temp_dir = tempdir().expect("tempdir should be created");
        let ca_dir = temp_dir.path().join("ca");

        generate_ca(&ca_dir, false).expect("first CA generation should succeed");
        let err = generate_ca(&ca_dir, false).expect_err("second generation should fail");
        assert!(
            err.to_string().contains("pass `--force`"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn generate_ca_force_overwrites_existing_material() {
        let temp_dir = tempdir().expect("tempdir should be created");
        let ca_dir = temp_dir.path().join("ca");

        let first = generate_ca(&ca_dir, false).expect("first generation should succeed");
        let first_key = fs::read_to_string(&first.key_path).expect("first key should be readable");

        let second = generate_ca(&ca_dir, true).expect("force regeneration should succeed");
        let second_key =
            fs::read_to_string(&second.key_path).expect("second key should be readable");

        assert_ne!(first_key, second_key, "force should rotate key material");
    }

    #[test]
    fn export_ca_cert_copies_generated_certificate() {
        let temp_dir = tempdir().expect("tempdir should be created");
        let ca_dir = temp_dir.path().join("ca");
        let generated = generate_ca(&ca_dir, false).expect("CA generation should succeed");
        let export_path = temp_dir.path().join("replayproxy-ca.pem");

        let exported_path = export_ca_cert(&ca_dir, &export_path, false).expect("export succeeds");
        assert_eq!(exported_path, export_path);

        let source = fs::read(&generated.cert_path).expect("source cert readable");
        let exported = fs::read(&export_path).expect("exported cert readable");
        assert_eq!(
            source, exported,
            "export should preserve exact certificate bytes"
        );
    }

    #[test]
    fn export_ca_cert_requires_force_to_overwrite_existing_file() {
        let temp_dir = tempdir().expect("tempdir should be created");
        let ca_dir = temp_dir.path().join("ca");
        generate_ca(&ca_dir, false).expect("CA generation should succeed");

        let export_path = temp_dir.path().join("replayproxy-ca.pem");
        fs::write(&export_path, "existing").expect("seed export file");
        let err = export_ca_cert(&ca_dir, &export_path, false).expect_err("export should fail");
        assert!(
            err.to_string().contains("pass `--force`"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn export_ca_cert_force_overwrites_existing_file() {
        let temp_dir = tempdir().expect("tempdir should be created");
        let ca_dir = temp_dir.path().join("ca");
        let generated = generate_ca(&ca_dir, false).expect("CA generation should succeed");
        let export_path = temp_dir.path().join("replayproxy-ca.pem");
        fs::write(&export_path, "existing").expect("seed export file");

        export_ca_cert(&ca_dir, &export_path, true).expect("forced export should succeed");
        let source = fs::read(&generated.cert_path).expect("source cert readable");
        let exported = fs::read(&export_path).expect("exported cert readable");
        assert_eq!(source, exported);
    }

    #[test]
    fn validate_ca_material_accepts_matching_cert_and_key() {
        let temp_dir = tempdir().expect("tempdir should be created");
        let ca_dir = temp_dir.path().join("ca");
        let generated = generate_ca(&ca_dir, false).expect("CA generation should succeed");

        validate_ca_material(&generated.cert_path, &generated.key_path)
            .expect("matching CA certificate/key should validate");
    }

    #[test]
    fn validate_ca_material_rejects_mismatched_cert_and_key() {
        let temp_dir = tempdir().expect("tempdir should be created");
        let first_dir = temp_dir.path().join("first");
        let second_dir = temp_dir.path().join("second");
        let first = generate_ca(&first_dir, false).expect("first CA generation should succeed");
        let second = generate_ca(&second_dir, false).expect("second CA generation should succeed");

        let err = validate_ca_material(&first.cert_path, &second.key_path)
            .expect_err("mismatched CA certificate/key should fail");
        assert!(
            err.to_string().contains("do not match"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn validate_ca_material_reports_missing_certificate() {
        let temp_dir = tempdir().expect("tempdir should be created");
        let ca_dir = temp_dir.path().join("ca");
        let generated = generate_ca(&ca_dir, false).expect("CA generation should succeed");
        fs::remove_file(&generated.cert_path).expect("remove generated certificate");

        let err = validate_ca_material(&generated.cert_path, &generated.key_path)
            .expect_err("missing certificate should fail");
        assert!(
            err.to_string().contains("read CA certificate"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn leaf_generator_sets_cn_and_san_for_hostname() {
        let temp_dir = tempdir().expect("tempdir should be created");
        let ca_dir = temp_dir.path().join("ca");
        let generated = generate_ca(&ca_dir, false).expect("CA generation should succeed");

        let generator = LeafCertGenerator::from_ca_files(&generated.cert_path, &generated.key_path)
            .expect("leaf generator should initialize");
        let leaf = generator
            .issue_for_host("Api.Example.Test")
            .expect("leaf cert issuance should succeed");

        let (_, pem_block) =
            super::parse_x509_pem(leaf.cert_pem.as_bytes()).expect("leaf cert PEM should parse");
        let (_, certificate) = super::parse_x509_certificate(&pem_block.contents)
            .expect("leaf certificate DER should parse");

        let cn_values: Result<Vec<_>, _> = certificate
            .subject()
            .iter_common_name()
            .map(|attr| attr.as_str())
            .collect();
        assert_eq!(
            cn_values.expect("CN should decode"),
            vec!["api.example.test"]
        );

        let san = certificate
            .subject_alternative_name()
            .expect("SAN extension lookup should succeed")
            .expect("SAN extension should exist");
        let has_matching_san = san.value.general_names.iter().any(|name| {
            matches!(
                name,
                GeneralName::DNSName(value) if *value == "api.example.test"
            )
        });
        assert!(
            has_matching_san,
            "leaf SAN should include requested host: {:?}",
            san.value.general_names
        );
    }

    #[test]
    fn leaf_generator_caches_certificates_by_normalized_hostname() {
        let temp_dir = tempdir().expect("tempdir should be created");
        let ca_dir = temp_dir.path().join("ca");
        let generated = generate_ca(&ca_dir, false).expect("CA generation should succeed");

        let generator = LeafCertGenerator::from_ca_files(&generated.cert_path, &generated.key_path)
            .expect("leaf generator should initialize");
        let first = generator
            .issue_for_host("API.EXAMPLE.TEST")
            .expect("first issuance should succeed");
        let second = generator
            .issue_for_host("api.example.test")
            .expect("second issuance should succeed");

        assert!(
            Arc::ptr_eq(&first, &second),
            "cache should return same in-memory cert material instance"
        );
        assert_eq!(first.cert_pem, second.cert_pem);
        assert_eq!(first.key_pem, second.key_pem);
    }

    #[test]
    fn leaf_generator_rejects_empty_hostname() {
        let temp_dir = tempdir().expect("tempdir should be created");
        let ca_dir = temp_dir.path().join("ca");
        let generated = generate_ca(&ca_dir, false).expect("CA generation should succeed");

        let generator = LeafCertGenerator::from_ca_files(&generated.cert_path, &generated.key_path)
            .expect("leaf generator should initialize");
        let err = generator
            .issue_for_host("   ")
            .expect_err("empty hostname should fail");
        assert!(
            err.to_string().contains("must not be empty"),
            "unexpected error: {err}"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_manual_instructions_include_expected_commands() {
        let instructions = linux_manual_install_instructions(Path::new("/tmp/ca/cert.pem"));
        assert!(
            instructions.contains("update-ca-certificates"),
            "instructions: {instructions}"
        );
        assert!(
            instructions.contains("trust anchor"),
            "instructions: {instructions}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn generated_ca_uses_restricted_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let temp_dir = tempdir().expect("tempdir should be created");
        let ca_dir = temp_dir.path().join("ca");
        let generated = generate_ca(&ca_dir, false).expect("CA generation should succeed");

        let dir_mode = fs::metadata(&ca_dir)
            .expect("ca dir should be readable")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(dir_mode, 0o700, "unexpected directory mode");

        let cert_mode = fs::metadata(generated.cert_path)
            .expect("cert should be readable")
            .permissions()
            .mode()
            & 0o777;
        let key_mode = fs::metadata(generated.key_path)
            .expect("key should be readable")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(cert_mode, 0o600, "unexpected cert mode");
        assert_eq!(key_mode, 0o600, "unexpected key mode");
    }
}
