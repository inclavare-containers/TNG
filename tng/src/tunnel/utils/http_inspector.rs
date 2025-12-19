use std::io::Cursor;

use anyhow::{bail, Context, Result};
use bytes::BytesMut;
use http::{uri::Authority, Uri};
use scopeguard::defer;
use tokio::io::{AsyncReadExt, AsyncWriteExt as _};
#[cfg(unix)]
use tokio::time as tokio_time;
#[cfg(wasm)]
use tokio_with_wasm::alias::time as tokio_time;

const HTTP_INSPECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

#[derive(Debug, PartialEq)]
pub enum RequestInfo {
    /// There is a HTTP1 request in the stream
    Http1 { authority: Authority, path: String },
    /// There is a HTTP2 request in the stream
    Http2 { authority: Authority, path: String },
    /// There is no HTTP request in the stream, and we got no error during the inspection, so we assume it's some protocol other than HTTP
    UnknownProtocol,
}

pub struct InspectionResult<T> {
    /// This is a "clone" of the original stream, which can be used to read and write just like the original stream.
    pub unmodified_stream: T,

    pub result: Result<RequestInfo>,
}

pub struct HttpRequestInspector {}

impl HttpRequestInspector {
    pub async fn inspect_stream(
        in_stream: impl tokio::io::AsyncRead + tokio::io::AsyncWrite + std::marker::Unpin,
    ) -> InspectionResult<impl tokio::io::AsyncRead + tokio::io::AsyncWrite + std::marker::Unpin>
    {
        let (mut stream1_reader, mut stream1_writer) = tokio::io::simplex(64);
        let (stream2_reader, mut stream2_writer) = tokio::io::simplex(64);

        let (multiplex_stop_sender, multiplex_stop_receiver) = tokio::sync::oneshot::channel();

        let multiplex_task = async {
            let (mut in_stream_reader, in_stream_writer) = tokio::io::split(in_stream);

            let mut buf = BytesMut::with_capacity(4096);
            let fut = async {
                loop {
                    let start = buf.len();
                    let read_bytes = in_stream_reader
                        .read_buf(&mut buf)
                        .await
                        .context("Failed to read from stream")?;
                    if read_bytes == 0 {
                        // whatever the stream is closed or the buffer capacity reached, we can stop the multiplex task now.
                        break;
                    }

                    // Send the data to the other two task and ignore all the errors.
                    let _ = tokio::join!(
                        stream1_writer.write_all(&buf[start..]),
                        stream2_writer.write_all(&buf[start..])
                    );

                    // This is a optimalization, to give a chance to the http request parser task to run so they can check the request as soon as possible.
                    tokio::task::yield_now().await;
                }

                Ok(())
            };

            let res = tokio::select! {
                res = fut => {
                    // If it is failed reading from the stream, we will return the error.
                    res
                }
                _ = multiplex_stop_receiver => {
                    Ok(())
                }
            };

            (
                tokio::io::join(Cursor::new(buf).chain(in_stream_reader), in_stream_writer),
                res,
            )
        };

        let try_http1 = async {
            let mut buf = BytesMut::with_capacity(4096);
            loop {
                stream1_reader
                    .read_buf(&mut buf)
                    .await
                    .context("Failed to read from stream")?;

                // Try to parse the request
                let mut headers = [httparse::EMPTY_HEADER; 16];
                let mut req = httparse::Request::new(&mut headers);
                let status = req.parse(&buf).context("Failed to parse http1 request")?;

                tracing::trace!(?req, "Got http1 request");
                match (
                    req.path,
                    req.headers
                        .iter()
                        .find(|r| r.name.eq_ignore_ascii_case("Host")),
                ) {
                    (Some(req_path), host) => {
                        // Accroding to RFC 9112, we have to accept the absolute-form in requests, even when host header is missing.
                        // https://datatracker.ietf.org/doc/html/rfc9112#name-absolute-form
                        let uri = req_path
                            .parse::<Uri>()
                            .context("Invalid path in http1 request")?;

                        if let Some(authority) = uri.authority() {
                            return Ok(RequestInfo::Http1 {
                                authority: authority.to_owned(),
                                path: uri.path().to_owned(),
                            });
                        } else if let Some(host) = host {
                            return Ok(RequestInfo::Http1 {
                                authority: Authority::try_from(host.value)
                                    .context("Invalid host header in http1 request")?,
                                path: uri.path().to_owned(),
                            });
                        } else {
                            // The missing of host header may be due to the incomplete request data, so we need to check here before returning an error.
                            if status.is_complete() {
                                bail!("Host header is missing in http1 request")
                            }
                        };
                    }
                    _ => {
                        if status.is_complete() {
                            bail!("Invalid http1 request, either host header or path are missing")
                        }
                        // Waiting for more data
                    }
                }

                if buf.len() == buf.capacity() {
                    bail!("Buffer is full, cannot parse http1 request because the request is larger than {}", buf.capacity());
                }
            }
        };

        let try_http2 = async {
            let stream = tokio::io::join(stream2_reader, tokio::io::empty());
            let mut connection = h2::server::handshake(stream).await?;
            if let Some(request) = connection.accept().await {
                let (request, _) = request.context("Failed to accept request")?;
                Ok(RequestInfo::Http2 {
                    authority: request
                        .uri()
                        .authority()
                        .context("Missing :authority header in request")?
                        .to_owned(),
                    path: request.uri().path().to_owned(),
                })
            } else {
                bail!("No http2 request received from the stream");
            }
        };

        let try_http1_or_http2 = async {
            defer! {
                let _ = multiplex_stop_sender.send(()); // Ignore the error here
            }

            let timeout = tokio_time::sleep(HTTP_INSPECT_TIMEOUT);

            tokio::select! {
                http1_or_http2 = async { tokio::join!(try_http1, try_http2) } => {
                    match http1_or_http2 {
                        (Ok(h1), _) => h1,
                        (Err(_), Ok(h2)) => h2,
                        (Err(h1_err), Err(h2_err)) => {
                            tracing::debug!("Failed to inspect tcp stream as both http1 and http2 request. HTTP1 error: {h1_err:#}, HTTP2 error: {h2_err:#}");
                            RequestInfo::UnknownProtocol
                        }
                    }
                },
                _ = timeout => {
                    tracing::debug!("Timeout waiting for inspecting http1 or http2 request from tcp stream");
                    RequestInfo::UnknownProtocol
                }
            }
        };

        match tokio::join!(multiplex_task, try_http1_or_http2) {
            // What ever wrong happened in the multiplex task failed, return the error.
            ((stream, Err(e)), _) => InspectionResult {
                unmodified_stream: stream,
                result: Err(e),
            },
            // Else, we return the result generated during http1 or http2 inspection.
            ((stream, Ok(_)), request_info) => InspectionResult {
                unmodified_stream: stream,
                result: Ok(request_info),
            },
        }
    }
}

#[cfg(test)]
mod tests {

    use anyhow::Result;
    use auto_enums::auto_enum;
    use axum::response::IntoResponse as _;
    use bytes::{BufMut, Bytes};
    use http::{HeaderValue, Request, StatusCode, Version};
    use http_body_util::BodyExt;
    use hyper::body::Body as _;
    use hyper_util::{
        rt::{TokioExecutor, TokioIo},
        service::TowerToHyperService,
    };
    use tower::ServiceBuilder;

    use super::*;

    enum HttpVersion {
        Http1,
        Http2,
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 10)]
    async fn test_http1_target_absolute_form() -> Result<()> {
        test_http_inspect_common(
            http::Request::builder()
                .uri("http://example.com:8080/this/is/a/path")
                .body("hello".to_string())?,
            RequestInfo::Http1 {
                authority: "example.com:8080".parse()?,
                path: "/this/is/a/path".to_string(),
            },
            HttpVersion::Http1,
        )
        .await
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 10)]
    async fn test_http1_target_normal_form() -> Result<()> {
        test_http_inspect_common(
            http::Request::builder()
                .uri("/this/is/a/path")
                .header("HOST", "example.com:8080")
                .body("hello".to_string())?,
            RequestInfo::Http1 {
                authority: "example.com:8080".parse()?,
                path: "/this/is/a/path".to_string(),
            },
            HttpVersion::Http1,
        )
        .await?;

        test_http_inspect_common(
            http::Request::builder()
                .uri("/this/is/a/path")
                .header("HOST", "example.com")
                .body("hello".to_string())?,
            RequestInfo::Http1 {
                authority: "example.com".parse()?,
                path: "/this/is/a/path".to_string(),
            },
            HttpVersion::Http1,
        )
        .await
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 10)]
    async fn test_http2() -> Result<()> {
        test_http_inspect_common(
            http::Request::builder()
                .uri("http://example.com:8080/this/is/a/path")
                .version(Version::HTTP_2)
                .body("hello".to_string())?,
            RequestInfo::Http2 {
                authority: "example.com:8080".parse()?,
                path: "/this/is/a/path".to_string(),
            },
            HttpVersion::Http2,
        )
        .await?;

        test_http_inspect_common(
            http::Request::builder()
                .uri("http://example.com:80/this/is/a/path")
                .version(Version::HTTP_2)
                .body("hello".to_string())?,
            RequestInfo::Http2 {
                authority: "example.com:80".parse()?,
                path: "/this/is/a/path".to_string(),
            },
            HttpVersion::Http2,
        )
        .await?;

        test_http_inspect_common(
            http::Request::builder()
                .uri("http://example.com/this/is/a/path")
                .version(Version::HTTP_2)
                .body("hello".to_string())?,
            RequestInfo::Http2 {
                authority: "example.com".parse()?,
                path: "/this/is/a/path".to_string(),
            },
            HttpVersion::Http2,
        )
        .await
    }

    #[auto_enum]
    async fn test_http_inspect_common(
        request: Request<String>,
        request_info: RequestInfo,
        http_version: HttpVersion,
    ) -> Result<()> {
        let mut expected_request = request;

        let content_len = expected_request
            .size_hint()
            .exact()
            .context("Failed to get size of body")?;
        expected_request.headers_mut().insert(
            http::header::CONTENT_LENGTH,
            HeaderValue::from_str(&content_len.to_string())?,
        );

        let (s1, s2) = tokio::io::duplex(4096);

        // Prepare a client to send requests to the server, and here we got the future for getting the response.
        #[auto_enum(Future)]
        let response_future = match http_version {
            HttpVersion::Http1 => {
                let (mut sender, conn) =
                    hyper::client::conn::http1::handshake(TokioIo::new(s1)).await?;
                #[allow(clippy::disallowed_methods)]
                tokio::spawn(async move {
                    conn.await
                        .context("The HTTP connection with upstream is broken")?;
                    Ok::<_, anyhow::Error>(())
                });

                sender.send_request(expected_request.clone())
            }
            HttpVersion::Http2 => {
                let (mut sender, conn) =
                    hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(s1))
                        .await?;
                #[allow(clippy::disallowed_methods)]
                tokio::spawn(async move {
                    conn.await
                        .context("The HTTP connection with upstream is broken")?;
                    Ok::<_, anyhow::Error>(())
                });

                sender.send_request(expected_request.clone())
            }
        };

        // Setup an inspection, and get the inspection result.
        let InspectionResult {
            unmodified_stream,
            result,
        } = HttpRequestInspector::inspect_stream(s2).await;

        // Check the inspection result of the request.
        let result = result?;
        assert_eq!(result, request_info);

        // Setup a http server to handle the request.
        let expected_request_cloned = expected_request.clone();
        #[allow(clippy::disallowed_methods)]
        tokio::spawn(async {
            let svc = {
                ServiceBuilder::new().service(tower::service_fn(
                    move |req: http::Request<hyper::body::Incoming>| {
                        let expected_request_cloned = expected_request_cloned.clone();
                        async move {
                            assert_eq!(req.uri(), expected_request_cloned.uri());
                            assert_eq!(req.method(), expected_request_cloned.method());
                            assert_eq!(req.version(), expected_request_cloned.version());
                            assert_eq!(req.headers(), expected_request_cloned.headers());
                            let mut body = req.into_body();
                            let frame = body.frame().await;
                            assert!(frame.is_some());
                            let frame = frame.unwrap()?;
                            assert_eq!(
                                frame.data_ref(),
                                Some(&Bytes::copy_from_slice(
                                    expected_request_cloned.body().as_bytes()
                                ))
                            );

                            Ok::<_, anyhow::Error>((StatusCode::OK, "ok").into_response())
                        }
                    },
                ))
            };
            let svc = TowerToHyperService::new(svc);
            if let Err(error) = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new())
                .serve_connection_with_upgrades(TokioIo::new(unmodified_stream), svc)
                .await
            {
                tracing::error!(?error, "Failed to serve connection");
            }

            Ok::<_, anyhow::Error>(())
        });

        // Get response and check the correctness of response
        let response = response_future.await?;
        assert_eq!(response.status(), StatusCode::OK);
        let mut body = response.into_body();
        let frame = body.frame().await;
        assert!(frame.is_some());
        let frame = frame.unwrap()?;
        assert_eq!(
            frame.data_ref(),
            Some(&Bytes::copy_from_slice("ok".as_bytes()))
        );

        assert!(body.frame().await.is_none());

        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 10)]
    async fn test_normal_tcp() -> Result<()> {
        test_http_inspect_on_normal_tcp_common(
            Bytes::from("Hello world\n"),
            Some(RequestInfo::UnknownProtocol),
        )
        .await?;

        let mut buffer = vec![0; 4096 * 10];
        tokio::io::repeat(0b101).read_exact(&mut buffer).await?;
        test_http_inspect_on_normal_tcp_common(
            Bytes::from_owner(buffer),
            Some(RequestInfo::UnknownProtocol),
        )
        .await
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 10)]
    async fn test_http_inspect_on_http1_raw() -> Result<()> {
        test_http_inspect_on_normal_tcp_common(
            Bytes::from("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"),
            Some(RequestInfo::Http1 {
                authority: "localhost".parse()?,
                path: "/".to_string(),
            }),
        )
        .await?;

        let mut buf = BytesMut::with_capacity(4096 * 10);
        buf.put_slice("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n".as_bytes());
        while buf.len() < 4096 {
            // To test what will happen when the buffer used in HttpRequestInspector is full.
            buf.put_slice("random aaaaa".as_bytes());
        }

        test_http_inspect_on_normal_tcp_common(
            buf.freeze(),
            Some(RequestInfo::Http1 {
                authority: "localhost".parse()?,
                path: "/".to_string(),
            }),
        )
        .await?;

        Ok(())
    }

    async fn test_http_inspect_on_normal_tcp_common(
        content: Bytes,
        expected_result: Option<RequestInfo>,
    ) -> Result<()> {
        // Setup an inspection, and get the inspection result.
        let InspectionResult {
            mut unmodified_stream,
            result,
        } = HttpRequestInspector::inspect_stream(Cursor::new(content.to_vec())).await;

        // Check the inspection result of the request.
        match expected_result {
            Some(request_info) => {
                assert_eq!(result?, request_info)
            }
            None => {
                assert!(result.is_err());
            }
        }

        // Check the content of the stream.
        let mut buf = Vec::new();
        unmodified_stream.read_to_end(&mut buf).await?;
        assert_eq!(buf, content);

        Ok(())
    }
}
