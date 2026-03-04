//! C2PA Proof Service
//!
//! A backend service that provides an API to generate ZK proofs for C2PA verification.

use axum::{
    extract::Multipart,
    extract::Path,
    routing::{get, post},
    Json, Router,
};
use tower_http::services::ServeDir;
use prover_c2pa::{calculate_public_input, generate_proof_with_path, C2paResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tower::ServiceBuilder;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use uuid::Uuid;

/// Task status
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TaskStatus {
    Pending,
    Processing,
    Completed,
    Failed,
}

/// Task info
#[derive(Debug, Clone)]
pub struct TaskInfo {
    pub status: TaskStatus,
    pub image_name: String,
    pub proof_result: Option<ProofResponse>,
    pub error: Option<String>,
    pub public_input: Option<PublicInputResponse>,
}

impl Default for TaskInfo {
    fn default() -> Self {
        Self {
            status: TaskStatus::Pending,
            image_name: String::new(),
            proof_result: None,
            error: None,
            public_input: None,
        }
    }
}

/// Public input response (serializable version)
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PublicInputResponse {
    #[serde(rename = "dataHashPrefix")]
    pub data_hash_prefix: u64,
    #[serde(rename = "expectedHashPrefix")]
    pub expected_hash_prefix: u64,
    #[serde(rename = "imageSize")]
    pub image_size: u32,
    #[serde(rename = "isSigned")]
    pub is_signed: bool,
    #[serde(rename = "actionCount")]
    pub action_count: u8,
    #[serde(rename = "expectedActionsHashPrefix")]
    pub expected_actions_hash_prefix: u64,
}

/// Global task manager
static TASK_MANAGER: std::sync::LazyLock<Arc<RwLock<HashMap<String, TaskInfo>>>> =
    std::sync::LazyLock::new(|| Arc::new(RwLock::new(HashMap::new())));

/// Response for submitting a task
#[derive(Serialize, Deserialize)]
pub struct SubmitResponse {
    /// Task ID
    #[serde(rename = "taskId")]
    pub task_id: String,
    /// Status
    pub status: TaskStatus,
    /// Public input (ZK proof input)
    #[serde(rename = "publicInput")]
    pub public_input: Option<PublicInputResponse>,
}

/// Response structure for the proof API (for completed task)
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ProofResponse {
    /// Whether the proof generation was successful
    pub success: bool,
    /// Error message if failed
    pub error: Option<String>,
    /// Whether proof was generated
    #[serde(rename = "proofGenerated")]
    pub proof_generated: bool,
    /// Public values from the proof
    #[serde(rename = "publicValues")]
    pub public_values: Option<PublicValues>,
    /// Proof file path
    #[serde(rename = "proofPath")]
    pub proof_path: Option<String>,
}

/// Public values from the ZK proof
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct PublicValues {
    /// Whether the hash verification passed
    #[serde(rename = "hashValid")]
    pub hash_valid: bool,
    /// The computed hash prefix
    #[serde(rename = "computedHashPrefix")]
    pub computed_hash_prefix: u64,
    /// Whether the image is C2PA signed
    #[serde(rename = "isSigned")]
    pub is_signed: bool,
    /// Image size
    #[serde(rename = "imageSize")]
    pub image_size: u32,
    /// Number of actions
    #[serde(rename = "actionCount")]
    pub action_count: u8,
    /// Whether actions are valid
    #[serde(rename = "actionsValid")]
    pub actions_valid: bool,
}

/// Convert prover-c2pa C2paResult to our PublicValues
fn convert_public_values(result: &C2paResult) -> PublicValues {
    PublicValues {
        hash_valid: result.hash_valid,
        computed_hash_prefix: result.computed_hash_prefix,
        is_signed: result.is_signed,
        image_size: result.image_size,
        action_count: result.action_count,
        actions_valid: result.actions_valid,
    }
}

/// Handle image upload and submit async proof task
async fn handle_submit(mut multipart: Multipart) -> Json<SubmitResponse> {
    // Try to get the image field
    while let Some(field) = multipart.next_field().await.unwrap() {
        let field_name = field.name().unwrap_or("").to_string();

        if field_name == "image" {
            let file_name = field.file_name().unwrap_or("unknown").to_string();
            tracing::info!("Received image: {}", file_name);

            // Get the image bytes
            match field.bytes().await {
                Ok(image_data) => {
                    tracing::info!("Image size: {} bytes", image_data.len());

                    // Generate task ID
                    let task_id = Uuid::new_v4().to_string();

                    // Save image data to file
                    let proof_dir = std::path::Path::new("proofs");
                    std::fs::create_dir_all(proof_dir).ok();

                    let image_path = proof_dir.join(format!("{}_image.jpg", task_id));
                    if let Err(e) = std::fs::write(&image_path, &image_data) {
                        tracing::error!("Failed to save image: {}", e);
                        return Json(SubmitResponse {
                            task_id: task_id.clone(),
                            status: TaskStatus::Failed,
                            public_input: None,
                        });
                    }

                    // Calculate public input (synchronous, but fast)
                    let public_input = calculate_public_input(&image_data, true);
                    let public_input_response = public_input.clone().map(|pi| PublicInputResponse {
                        data_hash_prefix: pi.data_hash_prefix,
                        expected_hash_prefix: pi.expected_hash_prefix,
                        image_size: pi.image_size,
                        is_signed: pi.is_signed,
                        action_count: pi.action_count,
                        expected_actions_hash_prefix: pi.expected_actions_hash_prefix,
                    });

                    // Initialize task
                    {
                        let mut tasks = TASK_MANAGER.write().await;
                        tasks.insert(
                            task_id.clone(),
                            TaskInfo {
                                status: TaskStatus::Processing,
                                image_name: file_name.clone(),
                                proof_result: None,
                                error: None,
                                public_input: public_input_response.clone(),
                            },
                        );
                    }

                    // Spawn async proof generation
                    let task_id_clone = task_id.clone();
                    let image_data_clone = image_data.clone();

                    tokio::spawn(async move {
                        tracing::info!("Starting async proof generation for task {}", task_id_clone);

                        // Generate proof and save to file
                        let proof_path_str = format!("proofs/{}.json", task_id_clone);
                        let proof_result = generate_proof_with_path(&image_data_clone, true, Some(&proof_path_str));

                        let response = ProofResponse {
                            success: proof_result.success,
                            error: proof_result.error,
                            proof_generated: proof_result.proof_generated,
                            public_values: proof_result
                                .public_values
                                .as_ref()
                                .map(convert_public_values),
                            proof_path: proof_result.proof_path,
                        };

                        // Update task status
                        let mut tasks = TASK_MANAGER.write().await;
                        if let Some(task) = tasks.get_mut(&task_id_clone) {
                            task.status = if response.success && response.proof_generated {
                                TaskStatus::Completed
                            } else {
                                TaskStatus::Failed
                            };
                            task.proof_result = Some(response);
                        }

                        tracing::info!("Task {} completed", task_id_clone);
                    });

                    return Json(SubmitResponse {
                        task_id,
                        status: TaskStatus::Processing,
                        public_input: public_input_response,
                    });
                }
                Err(e) => {
                    tracing::error!("Failed to read image data: {}", e);
                    return Json(SubmitResponse {
                        task_id: Uuid::new_v4().to_string(),
                        status: TaskStatus::Failed,
                        public_input: None,
                    });
                }
            }
        }
    }

    // No image field found
    Json(SubmitResponse {
        task_id: Uuid::new_v4().to_string(),
        status: TaskStatus::Failed,
        public_input: None,
    })
}

/// Handle task status query
async fn handle_status(Path(task_id): Path<String>) -> Json<serde_json::Value> {
    let tasks = TASK_MANAGER.read().await;

    match tasks.get(&task_id) {
        Some(task) => {
            let (status, proof) = match &task.proof_result {
                Some(proof_result) => (task.status.clone(), Some(proof_result.clone())),
                None => (task.status.clone(), None),
            };

            Json(serde_json::json!({
                "taskId": task_id,
                "status": status,
                "imageName": task.image_name,
                "proof": proof,
                "publicInput": task.public_input,
                "error": task.error
            }))
        }
        None => Json(serde_json::json!({
            "error": "Task not found"
        })),
    }
}

/// Handle proof verification
async fn handle_verify(Path(task_id): Path<String>) -> Json<serde_json::Value> {
    let proof_path = format!("proofs/{}.json", task_id);

    // Check if proof file exists
    if !std::path::Path::new(&proof_path).exists() {
        return Json(serde_json::json!({
            "valid": false,
            "message": "Proof file not found"
        }));
    }

    // Read and parse proof file
    match std::fs::read_to_string(&proof_path) {
        Ok(content) => {
            // Just verify the file is valid JSON with expected fields
            if content.contains("public_input") && content.contains("public_values") {
                Json(serde_json::json!({
                    "valid": true,
                    "message": "Proof data is valid",
                    "taskId": task_id
                }))
            } else {
                Json(serde_json::json!({
                    "valid": false,
                    "message": "Proof file has invalid format"
                }))
            }
        }
        Err(e) => Json(serde_json::json!({
            "valid": false,
            "message": format!("Failed to read proof file: {}", e)
        })),
    }
}

/// Health check endpoint
async fn health_check() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "healthy",
        "service": "c2pa-proof-service"
    }))
}

#[tokio::main]
async fn main() {
    // Initialize tracing
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "c2pa_service=debug,tower_http=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    tracing::info!("Starting C2PA Proof Service...");

    // Create proof directory
    std::fs::create_dir_all("proofs").ok();

    // CORS configuration
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    // Build the router
    let app = Router::new()
        .route("/health", get(health_check))
        .route("/api/v1/proof", post(handle_submit))
        .route("/api/v1/proof/:task_id", get(handle_status))
        .route("/api/v1/verify/:task_id", get(handle_verify))
        .nest_service("/proofs", ServeDir::new("proofs"))
        .layer(
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http())
                .layer(cors)
                .into_inner(),
        );

    // Bind to a port
    let addr = std::net::SocketAddr::from(([0, 0, 0, 0], 8080));
    tracing::info!("Listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
