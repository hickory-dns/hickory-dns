use std::mem;
use futures::{Future, IntoFuture, Poll, Async};

/// Future for the `select_any` combinator, waiting for one of any of a list of
/// futures to complete, unlike `select_all`, this future ignores all but the last
/// error, if there are any.
///
/// This is created by this `select_any` function.
#[must_use = "futures do nothing unless polled"]
pub struct SelectAny<A> where A: Future {
    inner: Vec<A>,
}

/// Creates a new future which will select over a list of futures.
///
/// The returned future will wait for any future within `list` to be ready. Unlike
/// select_all, this will only return the first successful completion, or the last
/// failure. This is useful in contexts where any success is desired and failures
/// are ignored, unless all the futures fail.
///
/// # Panics
///
/// This function will panic if the iterator specified contains no items.
pub fn select_any<I>(iter: I) -> SelectAny<<I::Item as IntoFuture>::Future>
    where I: IntoIterator,
          I::Item: IntoFuture,
{
    let ret = SelectAny {
        inner: iter.into_iter()
                   .map(|a| a.into_future())
                   .collect(),
    };
    assert!(ret.inner.len() > 0);
    ret
}

impl<A> Future for SelectAny<A>
    where A: Future,
{
    type Item = (A::Item, usize, Vec<A>);
    type Error = (A::Error, usize);

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        let item = self.inner.iter_mut().enumerate().filter_map(|(i, f)| {
            match f.poll() {
                Ok(Async::NotReady) => None,
                Ok(Async::Ready(e)) => Some((i, Ok(e))),
                Err(e) => Some((i, Err(e))),
            }
        }).next();
        match item {
            Some((idx, res)) => {
                drop(self.inner.remove(idx));
                match res {
                    Ok(e) => {
                      let rest = mem::replace(&mut self.inner, Vec::new());
                      Ok(Async::Ready((e, idx, rest)))
                    },
                    Err(e) => {
                      if self.inner.is_empty() {
                        Err((e, idx))
                      } else {
                        Ok(Async::NotReady)
                      }
                    },
                }
            }
            None => Ok(Async::NotReady),
        }
    }
}
