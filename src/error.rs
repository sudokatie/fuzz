use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("configuration error: {0}")]
    Config(String),

    #[error("target error: {0}")]
    Target(String),

    #[error("coverage error: {0}")]
    Coverage(String),

    #[error("corpus error: {0}")]
    Corpus(String),

    #[error("minimization error: {0}")]
    Minimize(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("database error: {0}")]
    Database(#[from] rusqlite::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
