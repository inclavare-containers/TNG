pub mod client;
mod path_rewrite;

use std::sync::Arc;

use crate::{
    config::{ingress::OHttpArgs, ra::RaArgs},
    error::TngError,
    tunnel::{endpoint::TngEndpoint, ingress::protocol::ohttp::security::client::OHttpClient},
    AttestationResult, TokioRuntime,
};
use anyhow::Result;

pub struct OHttpSecurityLayer {
    runtime: TokioRuntime,
    ohttp_client: Arc<OHttpClient>,
}

impl OHttpSecurityLayer {
    pub async fn new(
        #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
        transport_so_mark: Option<u32>,
        ohttp_args: &OHttpArgs,
        ra_args: RaArgs,
        runtime: TokioRuntime,
    ) -> Result<Self> {
        Ok(Self {
            runtime: runtime.clone(),
            ohttp_client: Arc::new(OHttpClient::new(
                runtime,
                ra_args,
                ohttp_args,
                #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
                transport_so_mark,
            )?),
        })
    }

    pub async fn prepare(&self) -> Result<()> {
        // Do nothing
        Ok(())
    }

    pub async fn forward_http_request<'a>(
        &self,
        endpoint: &'a TngEndpoint,
        request: axum::extract::Request,
    ) -> Result<(axum::response::Response, Option<AttestationResult>), TngError> {
        self.ohttp_client
            .forward_request(&endpoint, request)
            .await
            .map_err(|error| {
                tracing::error!(?error, "Failed to forward HTTP request");
                error
            })
    }

    // async fn handle_http_request_encrypt(
    //     endpoint: &TngEndpoint,
    //     request: http::Request<Incoming>,
    // ) -> Result<axum::response::Response> {
    //     let (parts, body) = request.into_parts();

    //     let is_websocket = {
    //         WebSocketUpgrade::from_request_parts(&mut parts.clone(), &Default::default())
    //             .await
    //             .is_ok()
    //     };

    //     if is_websocket {
    //         let websocket_upgrade =
    //             WebSocketUpgrade::from_request_parts(&mut parts, &Default::default())
    //                 .await
    //                 .unwrap();
    //         websocket_upgrade.on_upgrade(|mut socket: WebSocket| async { todo!() });
    //         todo!()
    //     } else {
    //         todo!()
    //     }

    //     todo!()
    // }
}

// use anyhow::{anyhow, Result};
// use async_trait::async_trait;
// use axum::{
//     body::{Body, Bytes, HttpBody},
//     extract::{
//         ws::{WebSocket, WebSocketUpgrade},
//         FromRequest, FromRequestParts, Request,
//     },
//     http::{header, Method, StatusCode},
//     response::{Html, IntoResponse},
//     routing::{get, on, post},
//     Router,
// };
// use futures::{SinkExt, StreamExt};
// use http::Response;
// use hyper::body::Incoming;
// use std::convert::Infallible;

// use crate::{CommonStreamTrait, TokioIo, TokioRuntime};

// pub struct HttpServer {
//     runtime: TokioRuntime,
// }

// impl HttpServer {
//     pub async fn new(runtime: TokioRuntime) -> Result<Self> {
//         Ok(Self { runtime })
//     }
//     pub async fn consume_stream(&self, in_stream: impl CommonStreamTrait) -> Result<()> {
//         let hyper_service = hyper::service::service_fn(move |request: Request<Incoming>| async {
//             Self::handle_http_request_encrypt(request).await
//         });

//         hyper_util::server::conn::auto::Builder::new(self.runtime.clone())
//             .serve_connection_with_upgrades(TokioIo::new(in_stream), hyper_service)
//             .await
//             .map_err(|err| anyhow!("Error while handling HTTP request: {}", err))
//     }

//     async fn handle_http_request_encrypt(request: Request<Incoming>) -> Result<Response<Body>> {
//         let (parts, body) = request.into_parts();

//         // let is_websocket = {
//         //     WebSocketUpgrade::from_request_parts(&mut parts.clone(), &Default::default())
//         //         .await
//         //         .is_ok()
//         // };

//         // if is_websocket {
//         //     let websocket_upgrade =
//         //         WebSocketUpgrade::from_request_parts(&mut parts, &Default::default())
//         //             .await
//         //             .unwrap();
//         //     websocket_upgrade.on_upgrade(|mut socket: WebSocket| async { todo!() });

//         //     todo!()
//         // } else {
//         //     todo!()
//         // }

//         todo!()
//     }
// }

// // 处理普通HTTP请求和chunked请求的处理器
// async fn handle_request(req: Request<Body>) -> Result<impl IntoResponse, (StatusCode, String)> {
//     let method = req.method().clone();
//     let uri = req.uri().clone();
//     let headers = req.headers().clone();
//     let body = req.into_body();

//     // 处理chunked请求 - 读取所有chunks
//     let body_data = hyper::body::to_bytes(body).await.map_err(|e| {
//         (
//             StatusCode::BAD_REQUEST,
//             format!("Failed to read body: {}", e),
//         )
//     })?;

//     // 构建响应，显示请求信息
//     let response_text = format!(
//         "Method: {}\nURI: {}\nHeaders: {:?}\nBody size: {} bytes",
//         method,
//         uri,
//         headers,
//         body_data.len()
//     );

//     Ok(([(header::CONTENT_TYPE, "text/plain")], response_text))
// }

// // WebSocket处理函数
// async fn websocket_handler(ws: WebSocketUpgrade) -> impl IntoResponse {
//     ws.on_upgrade(handle_socket)
// }

// // 实际处理WebSocket连接的函数
// async fn handle_socket(mut socket: WebSocket) {
//     // 发送欢迎消息
//     if let Err(e) = socket
//         .send(axum::extract::ws::Message::Text(
//             "Welcome to the WebSocket server!".to_string(),
//         ))
//         .await
//     {
//         eprintln!("Failed to send welcome message: {}", e);
//         return;
//     }

//     // 处理消息循环
//     while let Some(msg) = socket.recv().await {
//         match msg {
//             Ok(axum::extract::ws::Message::Text(text)) => {
//                 // 回显文本消息
//                 if let Err(e) = socket
//                     .send(axum::extract::ws::Message::Text(format!("Echo: {}", text)))
//                     .await
//                 {
//                     eprintln!("Failed to send text message: {}", e);
//                     break;
//                 }
//             }
//             Ok(axum::extract::ws::Message::Binary(data)) => {
//                 // 回显二进制消息
//                 if let Err(e) = socket.send(axum::extract::ws::Message::Binary(data)).await {
//                     eprintln!("Failed to send binary message: {}", e);
//                     break;
//                 }
//             }
//             Ok(axum::extract::ws::Message::Close(frame)) => {
//                 // 处理关闭消息
//                 if let Err(e) = socket.send(axum::extract::ws::Message::Close(frame)).await {
//                     eprintln!("Failed to send close message: {}", e);
//                 }
//                 break;
//             }
//             Ok(axum::extract::ws::Message::Ping(data)) => {
//                 // 回应pong消息
//                 if let Err(e) = socket.send(axum::extract::ws::Message::Pong(data)).await {
//                     eprintln!("Failed to send pong message: {}", e);
//                     break;
//                 }
//             }
//             Err(e) => {
//                 eprintln!("WebSocket error: {}", e);
//                 break;
//             }
//         }
//     }
// }

// // 统一处理函数，同时处理HTTP请求和WebSocket请求
// async fn unified_handler(ws: Option<WebSocketUpgrade>, req: Request<Body>) -> impl IntoResponse {
//     // 如果请求是一个WebSocket升级请求，则处理为WebSocket连接
//     if let Some(ws) = ws {
//         return websocket_handler(ws).await;
//     }

//     // 否则处理为普通HTTP请求
//     handle_request(req).await
// }

// // 主页处理器
// async fn root() -> Html<&'static str> {
//     Html(
//         r#"
//     <!DOCTYPE html>
//     <html>
//     <head>
//         <title>Axum HTTP Server</title>
//     </head>
//     <body>
//         <h1>Axum HTTP Server</h1>
//         <p>This server supports:</p>
//         <ul>
//             <li>HTTP/1.1</li>
//             <li>HTTP/2</li>
//             <li>Regular requests</li>
//             <li>Chunked requests</li>
//             <li>WebSocket connections</li>
//         </ul>
//         <p>Endpoints:</p>
//         <ul>
//             <li>GET / - This page</li>
//             <li>POST /echo - Echo service for regular and chunked requests</li>
//             <li>GET /ws - WebSocket endpoint</li>
//             <li>GET or POST /unified - Unified endpoint for both HTTP and WebSocket</li>
//         </ul>
//         <p>Example usage:</p>
//         <ul>
//             <li>HTTP request: curl http://127.0.0.1:3000/unified</li>
//             <li>WebSocket: websocat ws://127.0.0.1:3000/unified</li>
//         </ul>
//     </body>
//     </html>
//     "#,
//     )
// }

// // 创建应用路由
// fn create_app() -> Router {
//     Router::new()
//         .route("/", get(root))
//         .route("/echo", post(handle_request).get(handle_request))
//         .route("/ws", get(websocket_handler))
//         .route("/unified", get(unified_handler).post(unified_handler))
// }

// #[tokio::main]
// async fn main() -> Result<(), Box<dyn std::error::Error>> {
//     // 构建我们的应用路由
//     let app = create_app();

//     // 创建TCP监听器
//     let listener = tokio::net::TcpListener::bind("127.0.0.1:3000").await?;
//     println!("Listening on http://{}", listener.local_addr()?);
//     println!("Try:");
//     println!("  curl -X POST -d 'hello world' http://127.0.0.1:3000/echo");
//     println!("  curl -X POST -H 'Transfer-Encoding: chunked' -d 'chunked data' http://127.0.0.1:3000/echo");
//     println!("  websocket connection to ws://127.0.0.1:3000/ws");
//     println!("  unified endpoint: curl http://127.0.0.1:3000/unified");
//     println!("  unified websocket: websocat ws://127.0.0.1:3000/unified");

//     // 运行服务器
//     axum::serve(listener, app).await?;

//     Ok(())
// }
