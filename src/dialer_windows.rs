use crate::agent_source::{AgentDialer, ReadWriteStream};
use std::fs::OpenOptions;
use std::io;

pub const WINDOWS_DEFAULT_PIPE: &str = r"\\.\pipe\openssh-ssh-agent";

pub struct NamedPipeDialer {
    path: String,
}

impl NamedPipeDialer {
    pub fn new(path: String) -> Self {
        Self { path }
    }
}

impl AgentDialer for NamedPipeDialer {
    fn dial(&self) -> Result<Box<dyn ReadWriteStream>, io::Error> {
        let file = OpenOptions::new().read(true).write(true).open(&self.path)?;
        Ok(Box::new(file))
    }

    fn name(&self) -> &str {
        &self.path
    }
}

pub fn default_agent_path() -> Option<String> {
    Some(WINDOWS_DEFAULT_PIPE.to_string())
}
