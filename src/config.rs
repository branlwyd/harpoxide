use crate::proto;
use lazy_static::lazy_static;
use std::{
    io,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};

// TODO: parse config fields (host_name, mfa_regs) into more useful types when building Config

const DEFAULT_SESSION_DURATION: Duration = Duration::from_secs(300); // 5 minutes
const DEFAULT_SESSION_CREATION_RATE: f64 = 1.0; // 1 Hz

lazy_static! {
    static ref CONFIG: Mutex<Option<Arc<Config>>> = Mutex::new(None);
}

/// Config represents an immutable harpoxide configuration.
#[derive(Debug)]
pub struct Config {
    host_name: String,
    email: String,
    cert_dir: PathBuf,
    password_loc: PathBuf,
    key_file: PathBuf,
    mfa_regs: Vec<String>,
    session_duration: Duration,
    session_creation_rate: f64,
}

impl Config {
    /// Gets the current config. This will panic if no config has been successfully set yet.
    pub fn get() -> Arc<Config> {
        let cfg = CONFIG.lock().unwrap();
        Arc::clone(cfg.as_ref().unwrap())
    }

    fn set(new_cfg: Config) {
        let mut cfg = CONFIG.lock().unwrap();
        *cfg = Some(Arc::new(new_cfg));
    }

    /// Sets the current config by parsing a config from the given reader.
    /// Any existing config is replaced on success.
    pub fn set_from_pb(cfg_pb: proto::config::Config) -> io::Result<()> {
        Config::set(Config::from_pb(cfg_pb)?);
        Ok(())
    }

    /// The host name of the server.
    pub fn host_name(&self) -> &str {
        &self.host_name
    }

    /// The email address of the server admin. (Used for ACME only.)
    pub fn email(&self) -> &str {
        &self.email
    }

    /// The directory to use to store TLS certificates.
    pub fn certificate_dir(&self) -> &Path {
        &self.cert_dir
    }

    /// The location to use to store encrypted password data.
    pub fn password_location(&self) -> &Path {
        &self.password_loc
    }

    /// The location of the encrypted key file.
    pub fn key_file(&self) -> &Path {
        &self.key_file
    }

    /// Multi-factor authentication registration blobs.
    pub fn mfa_registrations(&self) -> &[String] {
        &self.mfa_regs
    }

    /// The duration of an unattended session.
    pub fn session_duration(&self) -> Duration {
        self.session_duration
    }

    /// The rate that new session creations (i.e. password login attempts) can be attempted per IP, in Hz.
    pub fn session_creation_rate(&self) -> f64 {
        self.session_creation_rate
    }

    fn from_pb(cfg_pb: proto::config::Config) -> io::Result<Config> {
        // Check fields of cfg_pb.
        if cfg_pb.host_name.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "host_name is required",
            ));
        }

        if cfg_pb.email.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "email is required",
            ));
        }

        if cfg_pb.cert_dir.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "cert_dir is required",
            ));
        }

        if cfg_pb.pass_loc.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "pass_loc is required",
            ));
        }

        if cfg_pb.key_file.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "key_file is required",
            ));
        }

        if !cfg_pb.alert_cmd.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "alert_cmd is unimplemented",
            ));
        }

        if !cfg_pb.session_duration_s.is_finite() || cfg_pb.session_duration_s < 0.0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "session_duration_s must be positive",
            ));
        }
        let sess_dur = if cfg_pb.session_duration_s > 0.0 {
            Duration::from_secs_f64(cfg_pb.session_duration_s)
        } else {
            DEFAULT_SESSION_DURATION
        };

        if !cfg_pb.new_session_rate.is_finite() || cfg_pb.new_session_rate < 0.0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "new_session_rate must be positive",
            ));
        }
        let sess_creation_rate = if cfg_pb.new_session_rate > 0.0 {
            cfg_pb.new_session_rate
        } else {
            DEFAULT_SESSION_CREATION_RATE
        };

        // Return the new config.
        Ok(Config {
            host_name: cfg_pb.host_name,
            email: cfg_pb.email,
            cert_dir: PathBuf::from(cfg_pb.cert_dir),
            password_loc: PathBuf::from(cfg_pb.pass_loc),
            key_file: PathBuf::from(cfg_pb.key_file),
            mfa_regs: cfg_pb.mfa_reg,
            session_duration: sess_dur,
            session_creation_rate: sess_creation_rate,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{Config, DEFAULT_SESSION_CREATION_RATE, DEFAULT_SESSION_DURATION};
    use crate::proto;
    use lazy_static::lazy_static;
    use std::{io, path::Path, time::Duration};

    lazy_static! {
        static ref CONFIG_PB: proto::config::Config = {
            proto::config::Config {
                host_name: String::from("host_name value"),
                email: String::from("email value"),
                cert_dir: String::from("cert_dir value"),
                pass_loc: String::from("pass_loc value"),
                key_file: String::from("key_file value"),
                mfa_reg: Vec::from([
                    String::from("mfa_reg value 0"),
                    String::from("mfa_reg value 1"),
                ]),
                session_duration_s: 45.3,
                new_session_rate: 2.5,
                ..Default::default()
            }
        };
    }

    #[test]
    fn from_pb() {
        let cfg = Config::from_pb(CONFIG_PB.clone()).unwrap();
        assert_eq!(cfg.host_name(), CONFIG_PB.host_name);
        assert_eq!(cfg.email(), CONFIG_PB.email);
        assert_eq!(cfg.certificate_dir(), Path::new(&CONFIG_PB.cert_dir));
        assert_eq!(cfg.password_location(), Path::new(&CONFIG_PB.pass_loc));
        assert_eq!(cfg.key_file(), Path::new(&CONFIG_PB.key_file));
        assert_eq!(cfg.mfa_registrations(), CONFIG_PB.mfa_reg);
        assert_eq!(
            cfg.session_duration(),
            Duration::from_secs_f64(CONFIG_PB.session_duration_s)
        );
        assert_eq!(cfg.session_creation_rate(), CONFIG_PB.new_session_rate);
    }

    #[test]
    fn from_pb_defaults() {
        let mut cfg_pb = CONFIG_PB.clone();
        cfg_pb.session_duration_s = 0.0;
        cfg_pb.new_session_rate = 0.0;
        let cfg = Config::from_pb(cfg_pb).unwrap();
        assert_eq!(cfg.session_duration(), DEFAULT_SESSION_DURATION);
        assert_eq!(cfg.session_creation_rate(), DEFAULT_SESSION_CREATION_RATE);
    }

    #[test]
    fn from_pb_sanity_checking() {
        assert_causes_parse_error(|c| c.host_name = String::new());
        assert_causes_parse_error(|c| c.email = String::new());
        assert_causes_parse_error(|c| c.cert_dir = String::new());
        assert_causes_parse_error(|c| c.pass_loc = String::new());
        assert_causes_parse_error(|c| c.key_file = String::new());

        assert_causes_parse_error(|c| c.alert_cmd = String::from("alert_cmd value"));

        assert_causes_parse_error(|c| c.session_duration_s = -1.0);
        assert_causes_parse_error(|c| c.session_duration_s = f64::NAN);
        assert_causes_parse_error(|c| c.session_duration_s = f64::INFINITY);
        assert_causes_parse_error(|c| c.session_duration_s = f64::NEG_INFINITY);

        assert_causes_parse_error(|c| c.new_session_rate = -1.0);
        assert_causes_parse_error(|c| c.new_session_rate = f64::NAN);
        assert_causes_parse_error(|c| c.new_session_rate = f64::INFINITY);
        assert_causes_parse_error(|c| c.new_session_rate = f64::NEG_INFINITY);
    }

    fn assert_causes_parse_error<F: Fn(&mut proto::config::Config)>(f: F) {
        let mut cfg_pb = CONFIG_PB.clone();
        f(&mut cfg_pb);
        assert_eq!(
            Config::from_pb(cfg_pb).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
    }
}
