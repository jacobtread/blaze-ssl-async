/// Takes a poll type with a nested result type and handles the
/// pending and error states by returning
#[macro_export]
macro_rules! try_ready {
    ($e:expr) => {
        match $e {
            std::task::Poll::Ready(t) => match t {
                Ok(v) => v,
                Err(e) => return std::task::Poll::Ready(Err(e)),
            },
            std::task::Poll::Pending => {
                return std::task::Poll::Pending;
            }
        }
    };
}

/// Same as the try_ready macro but calls .into() on the error type
/// to map it to another error type
#[macro_export]
macro_rules! try_ready_into {
    ($e:expr) => {
        match $e {
            std::task::Poll::Ready(t) => match t {
                Ok(v) => v,
                Err(e) => return std::task::Poll::Ready(Err(e.into())),
            },
            std::task::Poll::Pending => {
                return std::task::Poll::Pending;
            }
        }
    };
}

macro_rules! ready_err {
    ($e:expr) => {
        return std::task::Poll::Ready(Err($e))
    };
}
