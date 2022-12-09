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
    msg: Option<String>,
    source: Option<BoxError>,
}

impl Error {
    pub(crate) fn new<E>(kind: Kind, msg: Option<String>, source: Option<E>) -> Error
        where
            E: Into<BoxError>,
    {
        Error {
            inner: Box::new(Inner {
                kind,
                msg,
                source: source.map(Into::into),
            }),
        }
    }

    pub(crate) fn new_msg(kind: Kind, msg: Option<String>) -> Error
    {
        Error {
            inner: Box::new(Inner {
                kind,
                msg,
                source: None
            }),
        }
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

        if let Some(ref msg) = self.inner.msg {
            builder.field("msg", msg);
        }

        if let Some(ref source) = self.inner.source {
            builder.field("source", source);
        }

        builder.finish()
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.inner.kind {
            Kind::Conversion => f.write_str("conversion error")?,
            Kind::Validation => f.write_str("validation error")?,
            Kind::Fetch => f.write_str("fetch error")?,
            Kind::Io => f.write_str("io error")?,
            Kind::Cert => f.write_str("cert error")?,
        };

        if let Some(msg) = &self.inner.msg {
            write!(f, ": {}", msg)?;
        }

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
    Conversion,
    Validation,
    Fetch,
    Io,
    Cert,
}

// constructors

pub(crate) fn conversion<E: Into<BoxError>>(e: E, msg: Option<String>) -> Error {
    Error::new(Kind::Conversion, msg, Some(e))
}

pub(crate) fn fetch<E: Into<BoxError>>(e: E, msg: Option<String>) -> Error {
    Error::new(Kind::Fetch, msg, Some(e))
}

pub(crate) fn io<E: Into<BoxError>>(e: E, msg: Option<String>) -> Error {
    Error::new(Kind::Io, msg, Some(e))
}

pub(crate) fn map_io_err<E: Into<BoxError>>(e: E) -> Error {
    io(e, None)
}

pub(crate) fn cert(msg: Option<String>) -> Error {
    Error::new_msg(Kind::Cert, msg)
}

pub(crate) fn map_conversion_err<E: Into<BoxError>>(e: E) -> Error {
    conversion(e, None)
}