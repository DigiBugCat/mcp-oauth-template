use anyhow::Result;
use axum::{
    routing::get,
    Router,
    http::header,
};
use rmcp::{
    transport::sse_server::{SseServer, SseServerConfig},
    ServerHandler,
    model::*,
    tool, tool_router, tool_handler,
    service::{NotificationContext, RoleServer},
    handler::server::router::tool::ToolRouter,
    Error as McpError,
};
use std::{net::SocketAddr, sync::Arc, future::Future};
use tokio::sync::Mutex;
use tower::ServiceBuilder;
use tower_http::{cors::CorsLayer, trace::TraceLayer};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use tokio_util::sync::CancellationToken;
use std::time::Duration;
use chrono::Utc;

#[derive(Debug, Clone)]
pub struct McpServer {
    counter: Arc<Mutex<i32>>,
    notes: Arc<Mutex<Vec<String>>>,
    tool_router: ToolRouter<Self>,
}

#[tool_router]
impl McpServer {
    pub fn new() -> Self {
        Self {
            counter: Arc::new(Mutex::new(0)),
            notes: Arc::new(Mutex::new(Vec::new())),
            tool_router: Self::tool_router(),
        }
    }

    #[tool(description = "Get the current time")]
    async fn get_time(&self) -> Result<CallToolResult, McpError> {
        let now = Utc::now();
        Ok(CallToolResult::success(vec![Content::text(format!(
            "Current time: {}",
            now.format("%Y-%m-%d %H:%M:%S UTC")
        ))]))
    }

    #[tool(description = "Increment the counter by 1")]
    async fn increment_counter(&self) -> Result<CallToolResult, McpError> {
        let mut counter = self.counter.lock().await;
        *counter += 1;
        Ok(CallToolResult::success(vec![Content::text(format!(
            "Counter incremented to: {}",
            *counter
        ))]))
    }

    #[tool(description = "Get the current counter value")]
    async fn get_counter(&self) -> Result<CallToolResult, McpError> {
        let counter = self.counter.lock().await;
        Ok(CallToolResult::success(vec![Content::text(format!(
            "Current counter value: {}",
            *counter
        ))]))
    }

    #[tool(description = "Get system information")]
    async fn system_info(&self) -> Result<CallToolResult, McpError> {
        let info = format!(
            "MCP Server\n\
             Version: 0.1.0\n\
             Platform: {}\n\
             Available tools: 4",
            std::env::consts::OS
        );
        Ok(CallToolResult::success(vec![Content::text(info)]))
    }

    #[tool(description = "Clear all notes")]
    async fn clear_notes(&self) -> Result<CallToolResult, McpError> {
        let mut notes = self.notes.lock().await;
        let count = notes.len();
        notes.clear();
        Ok(CallToolResult::success(vec![Content::text(format!(
            "Cleared {} notes",
            count
        ))]))
    }

    #[tool(description = "List all stored notes")]
    async fn list_notes(&self) -> Result<CallToolResult, McpError> {
        let notes = self.notes.lock().await;
        if notes.is_empty() {
            Ok(CallToolResult::success(vec![Content::text("No notes stored")]))
        } else {
            let notes_list = notes.iter().enumerate()
                .map(|(i, note)| format!("{}. {}", i + 1, note))
                .collect::<Vec<_>>()
                .join("\n");
            Ok(CallToolResult::success(vec![Content::text(notes_list)]))
        }
    }
}

#[tool_handler]
impl ServerHandler for McpServer {
    fn get_info(&self) -> ServerInfo {
        InitializeResult {
            protocol_version: ProtocolVersion::default(),
            capabilities: ServerCapabilities::builder()
                .enable_tools()
                .build(),
            server_info: Implementation {
                name: "MCP Server".to_string(),
                version: "0.1.0".to_string(),
            },
            instructions: None,
        }
    }

    async fn on_progress(
        &self,
        notification: ProgressNotificationParam,
        _context: NotificationContext<RoleServer>,
    ) {
        tracing::info!(
            "Progress notification: {:?} - {}",
            notification.progress_token,
            notification.progress
        );
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "mcp_server=info,tower_http=info".into()),
        )
        .with(tracing_subscriber::fmt::layer()
            .with_target(false)
            .with_thread_ids(false)
            .with_file(false)
            .with_line_number(false))
        .init();

    tracing::info!("Starting MCP Server...");

    // Create MCP server instance
    let mcp_server = McpServer::new();

    // Create SSE server config
    let sse_config = SseServerConfig {
        bind: SocketAddr::from(([0, 0, 0, 0], 8080)),
        sse_path: "/mcp".to_string(),  // For dev, serve at /mcp to work with OAuth
        post_path: "/mcp".to_string(),  // And POST at /mcp too
        ct: CancellationToken::new(),
        sse_keep_alive: Some(Duration::from_secs(15)),
    };
    
    // Create SSE server
    let (sse_server, sse_router) = SseServer::new(sse_config);

    // Create the MCP service
    let _sse_service = sse_server.with_service(move || mcp_server.clone());

    // Build the main router
    let app = Router::new()
        // Health check
        .route("/health", get(|| async { "OK" }))
        
        // Fallback to SSE routes
        .fallback_service(sse_router)
        
        // Add global middleware
        .layer(
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http()
                    .on_request(|request: &axum::http::Request<_>, _span: &tracing::Span| {
                        tracing::info!("📨 Request: {} {}", request.method(), request.uri());
                        tracing::debug!("📨 Headers: {:?}", request.headers());
                    })
                    .on_response(|response: &axum::http::Response<_>, latency: Duration, _span: &tracing::Span| {
                        tracing::info!("📤 Response: {} in {:?}", response.status(), latency);
                    }))
                .layer(CorsLayer::permissive()
                    .allow_headers(vec![
                        header::AUTHORIZATION,
                        header::CONTENT_TYPE,
                    ])),
        );

    // Start the server
    tracing::info!("MCP Server listening on http://0.0.0.0:8080");
    tracing::info!("SSE endpoint: GET /mcp");
    tracing::info!("JSON-RPC endpoint: POST /mcp");
    tracing::info!("Health check: GET /health");

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await?;
    axum::serve(listener, app).await?;

    Ok(())
}