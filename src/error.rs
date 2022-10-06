#![cfg_attr(target_arch = "wasm32", allow(unused))]
use std::error::Error as StdError;
use std::fmt;
use std::io;

pub type Result<T> = std::result::Result<T, Error>;

pub struct Error {
    inner: Box<Inner>,
}

pub(crate) type BoxError = Box<dyn StdError + Send + Sync>;

struct Inner {
    kind: Kind,
    source: Option<BoxError>,
}

impl Error {
    pub(crate) fn new<E>(kind: Kind, source: Option<E>) -> Error
        where
            E: Into<BoxError>,
    {
        Error {
            inner: Box::new(Inner {
                kind,
                source: source.map(Into::into),
            }),
        }
    }

    /// Returns true if the error is related to a fetch / reqwest
    pub fn is_fetch(&self) -> bool {
        matches!(self.inner.kind, Kind::Fetch)
    }

    /// Returns true if the error is related to io
    pub fn is_io(&self) -> bool {
        matches!(self.inner.kind, Kind::Io)
    }

    #[allow(unused)]
    pub(crate) fn into_io(self) -> io::Error {
        io::Error::new(io::ErrorKind::Other, self)
    }
}

impl fmt::Debug for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut builder = f.debug_struct("sev_snp_utils::Error");

        builder.field("kind", &self.inner.kind);

        if let Some(ref source) = self.inner.source {
            builder.field("source", source);
        }

        builder.finish()
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.inner.kind {
            Kind::Fetch => f.write_str("fetch error")?,
            Kind::Io => f.write_str("io error")?,
        };

        if let Some(e) = &self.inner.source {
            write!(f, ": {}", e)?;
        }

        Ok(())
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        self.inner.source.as_ref().map(|e| &**e as _)
    }
}

#[derive(Debug)]
pub(crate) enum Kind {
    Fetch,
    Io,
}

// constructors

pub(crate) fn fetch<E: Into<BoxError>>(e: E) -> Error {
    Error::new(Kind::Fetch, Some(e))
}

pub(crate) fn io<E: Into<BoxError>>(e: E) -> Error {
    Error::new(Kind::Io, Some(e))
}
