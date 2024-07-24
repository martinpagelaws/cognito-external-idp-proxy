use aws_config::{self, BehaviorVersion};
use aws_sdk_dynamodb::{self as dynamodb, types::AttributeValue};
use aws_sdk_secretsmanager as secretsmanager;
use jsonwebtoken::{encode, Header, EncodingKey, Algorithm};
use lambda_http::{run, service_fn, tracing, Body, Error, Request, Response};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use serde_qs;
use std::{fmt, result, env};
use std::time::SystemTime;

#[derive(Debug, PartialEq, Deserialize)]
struct RequestBody {
    grant_type: String,
    client_id: String,
    redirect_uri: String,
    client_secret: String,
    code: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct TokenRequestBody {
    grant_type: String,
    client_id: String,
    redirect_uri: String,
    code_verifier: String,
    client_assertion: String,
    client_assertion_type: String,
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

fn verify_request_body(request: &RequestBody) -> ValidationResult<&RequestBody> {
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
    let original_request: RequestBody = serde_qs::from_str(event_body).unwrap();

    match verify_request_body(&original_request) {
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

    let private_key_string = private_key.secret_string().unwrap();
    let private_key_jwk: jsonwebkey::JsonWebKey = private_key_string.parse().unwrap();
    let private_key_pem = private_key_jwk.key.to_pem();

    // Create JWT
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
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(private_key_jwk.key_id).expect("KID missing in private key");

    // Sign JWT
    let encoding_key: &EncodingKey = &EncodingKey::from_rsa_pem(&private_key_pem.as_bytes()).unwrap();
    let signed_token = encode(&header, &claims, &encoding_key).unwrap();

    // retrieve code_verifier if PKCE is used
    let mut code_verifier: Option<String> = None;
    if env::var("Pkce").expect("Pkce not set in env.").to_lowercase() == "true" {
        println!("USING PKCE");
        let dynamodb_client = dynamodb::Client::new(&config);
        let dynamodb_query = dynamodb_client.get_item()
            .table_name(env::var("DynamoDbCodeTable").expect("DynamoDbCodeTable not set in env."))
            .key("auth_code", AttributeValue::S(original_request.code.clone()))
            .attributes_to_get("code_verifier")
            .send()
            .await?;
        code_verifier = Some(dynamodb_query.item().unwrap().get("code_verifier").unwrap().as_s().unwrap().to_string());
    }

    // Craft request to IDP
    let payload = TokenRequestBody {
        client_assertion: signed_token,
        client_assertion_type: "urn:ietf:params:oauth:client-assertion-type:jwt-bearer".to_string(),
        client_id: client_id,
        grant_type: "authorization_code".to_string(),
        redirect_uri: env::var("ResponseUri").expect("ResponseUri env var missing"),
        code_verifier: code_verifier.unwrap_or("None".to_string()),
        code: original_request.code,
    };
    let payload = serde_urlencoded::to_string(&payload).expect("failed to serialize payload");

    // Make the token request
    let token_request_client = reqwest::Client::new();
    let res = token_request_client.post(idp_token_endpoint)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(payload)
        .send()
        .await?;
    let res_body: Value = res.json().await?;
    
    // Return the response
    let resp = Response::builder()
        .status(200)
        .header("content-type", "text/html")
        .body(res_body.to_string().into())
        .map_err(Box::new)?;
    Ok(resp)
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    tracing::init_default_subscriber();

    run(service_fn(function_handler)).await
}
