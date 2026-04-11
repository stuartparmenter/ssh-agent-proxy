use crate::agent_source::{AgentDialer, ReadWriteStream};
use std::io;
use std::os::unix::net::UnixStream;

pub struct UnixDialer {
    path: String,
}

impl UnixDialer {
    pub fn new(path: String) -> Self {
        Self { path }
    }
}

impl AgentDialer for UnixDialer {
    fn dial(&self) -> Result<Box<dyn ReadWriteStream>, io::Error> {
        let stream = UnixStream::connect(&self.path)?;
        Ok(Box::new(stream))
    }

    fn name(&self) -> &str {
        &self.path
    }
}

pub fn default_agent_path() -> Option<String> {
    std::env::var("SSH_AUTH_SOCK")
        .ok()
        .filter(|s| !s.is_empty())
}
