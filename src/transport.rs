use tokio::io::{self, AsyncRead, AsyncWrite};

use crate::LARGE_BUFFER_SIZE;

/// Bidirectional data relay between two streams.
///
/// Each direction is copied until EOF, at which point only that direction's
/// write half is shut down; the opposite direction keeps running. This is what
/// makes half-close work — a client that sends a request and then shuts down
/// its write side still receives the full response. Returns once both
/// directions have completed, or on the first error.
pub async fn transport<A, B>(mut a: A, mut b: B) -> io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin + Send,
    B: AsyncRead + AsyncWrite + Unpin + Send,
{
    // copy_bidirectional_with_sizes drives both directions on a single task,
    // avoiding the two spawns and the Arc<Mutex>-backed `io::split` that the
    // previous implementation needed.
    io::copy_bidirectional_with_sizes(&mut a, &mut b, LARGE_BUFFER_SIZE, LARGE_BUFFER_SIZE).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn test_transport() {
        let (mut client_a, server_a) = duplex(1024);
        let (server_b, mut client_b) = duplex(1024);

        let handle = tokio::spawn(async move {
            transport(server_a, server_b).await.ok();
        });

        client_a.write_all(b"hello").await.unwrap();
        client_a.shutdown().await.unwrap();

        let mut buf = vec![0u8; 1024];
        let n = client_b.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hello");

        // The relay stays open until BOTH directions close, so the b->a side
        // has to be closed too before it returns. That is the half-close
        // contract: a client shutting down its write side must still be able
        // to receive the rest of the response.
        client_b.shutdown().await.unwrap();
        drop(client_b);
        handle.await.ok();
    }

    #[tokio::test]
    async fn test_transport_half_close_does_not_truncate_response() {
        let (mut client_a, server_a) = duplex(1024);
        let (server_b, mut client_b) = duplex(1024);

        tokio::spawn(async move {
            transport(server_a, server_b).await.ok();
        });

        // Client sends a request and immediately half-closes, as curl and
        // many HTTP clients do.
        client_a.write_all(b"request").await.unwrap();
        client_a.shutdown().await.unwrap();

        let mut got = vec![0u8; 7];
        client_b.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"request");

        // The response must still make it back across the relay.
        let response = b"a-response-sent-after-the-client-half-closed";
        client_b.write_all(response).await.unwrap();
        client_b.flush().await.unwrap();

        let mut buf = vec![0u8; response.len()];
        client_a.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, response, "response was truncated by the relay");
    }

    #[tokio::test]
    async fn test_transport_no_leaked_tasks() {
        // Verify that when one side closes, both tasks complete promptly
        let (client_a, server_a) = duplex(1024);
        let (server_b, client_b) = duplex(1024);

        let handle = tokio::spawn(async move {
            transport(server_a, server_b).await.ok();
        });

        // Drop both client ends immediately
        drop(client_a);
        drop(client_b);

        // Transport should complete quickly, not hang forever
        let result = tokio::time::timeout(std::time::Duration::from_secs(1), handle).await;
        assert!(
            result.is_ok(),
            "transport should not hang when both sides are dropped"
        );
    }
}
