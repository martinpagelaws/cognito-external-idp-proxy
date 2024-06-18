use aws_config::{self, BehaviorVersion};
use aws_sdk_secretsmanager as secretsmanager;
use jsonwebtoken::{encode, Header, EncodingKey, Algorithm};
use lambda_http::{run, service_fn, tracing, Body, Error, Request, RequestExt, Response};
use serde::Deserialize;
use serde_json::json;
use serde_qs;
use std::{fmt, result, env};
use std::time::{Duration, SystemTime};

#[derive(Debug, PartialEq, Deserialize)]
struct RequestBody {
    grant_type: String,
    client_id: String,
    redirect_uri: String,
    client_secret: String,
    code: String,
}

#[derive(Debug, PartialEq, Deserialize)]
struct EnvVars;

type ValidationResult<T> = result::Result<T, RequestValidationError>;

#[derive(Debug, Clone)]
struct RequestValidationError;

impl fmt::Display for RequestValidationError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "invalid request")
    }
}

fn verify_request_body(request: RequestBody) -> ValidationResult<RequestBody> {
    if request.client_id != env::var("ClientId").expect("ClientId env var missing") { 
        Err(RequestValidationError) 
    } else if request.client_secret != env::var("ClientSecret").expect("ClientSecret env var missing") {
        Err(RequestValidationError)
    } else {
        Ok(request)
    }
}

async fn function_handler(event: Request) -> Result<Response<Body>, Error> {
    // Extract request details from Cognito 
    let event_body = std::str::from_utf8(event.body()).expect("Body not utf-8");
    println!("EVENT BODY");
    println!("{:?}", event_body);

    let original_request: RequestBody = serde_qs::from_str(event_body).unwrap();

    match verify_request_body(original_request) {
        Ok(_) => println!("Original request is valid - proceeding."),
        Err(e) => println!("Error: {}", e),
    }

    // Initialize AWS config
    let config = aws_config::defaults(BehaviorVersion::latest()).load().await;

    // let pkce_toggle = env::var("Pkce").unwrap_or("false".to_string()).to_lowercase();
    
    // Get private key from Secrets Manager
    let sm_client = secretsmanager::Client::new(&config);

    let private_key = sm_client
        .get_secret_value()
        .secret_id(env::var("SecretsManagerPrivateKey").expect("SecretsManagerPrivateKey env var missing"))
        .send()
        .await?;

    println!("PRIVATE KEY {:?}", private_key);

    // Create and sign the JWT
    let current_time = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
    let expiration_time = current_time + 300;
    let client_id = env::var("ClientId").expect("ClientId env var missing");
    let idp_issuer_url: &String = &env::var("IdpIssuerUrl").expect("IdpIssuerUrl env var missing");
    let idp_token_path: &String = &env::var("IdpTokenPath").expect("IdpTokenPath env var missing");
    let idp_token_endpoint = format!("{idp_issuer_url}{idp_token_path}");
    let claims = json!({
        "iss": client_id,
        "sub": client_id,
        "aud": idp_token_endpoint,
        "iat": current_time,
        "exp": expiration_time,
    });
    println!("CLAIMS {}", claims);
    
    // Craft request to IDP
    
    // Make the token request
    
    // Return the response
    let resp = Response::builder()
        .status(200)
        .header("content-type", "text/html")
        .body("HI".into())
        .map_err(Box::new)?;
    Ok(resp)
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    tracing::init_default_subscriber();

    run(service_fn(function_handler)).await
}
