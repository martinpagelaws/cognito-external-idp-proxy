use aws_config::{self, BehaviorVersion};
use aws_sdk_dynamodb::{self as dynamodb, types::AttributeValue};
use aws_sdk_secretsmanager::{self as secretsmanager};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use lambda_http::{run, service_fn, tracing, Body, Error, Request, RequestExt, Response};
//use lambda_runtime::{service_fn, run, Error, LambdaEvent};
use sha2::{Sha256, Digest};
use std::{env, time::SystemTime};
use url::Url;

#[derive(Clone)]
struct Clients {
    dynamodb_client: dynamodb::Client,
    sm_client: secretsmanager::Client,
}

async fn function_handler(clients: &Clients, event: Request) -> Result<Response<Body>, Error> {

    // Collect original Cognito request details from query string parameters
    let original_params = event.query_string_parameters_ref().unwrap();

    // Get random string from secrets manager as the code_verifier
    let random_password = clients.sm_client
        .get_random_password()
        .password_length(64)
        .exclude_punctuation(true)
        .include_space(false)
        .send()
        .await?;
    let code_verifier = random_password.random_password().unwrap();

    // Hash the code_verifier to send it as the code_challenge during authorize call
    let mut code_hasher = Sha256::new();
    code_hasher.update(code_verifier.as_bytes());
    let code_challenge = code_hasher.finalize();
    let code_challenge_base64 = URL_SAFE_NO_PAD.encode(code_challenge);

    // retrieve state from Cognito request and hash it to keep item key short in dynamodb
    let cognito_state = original_params.first("state").unwrap();
    let mut state_hasher = Sha256::new();
    state_hasher.update(cognito_state.as_bytes());
    let state_hash = format!("{:x}", state_hasher.finalize());

    // create ttl timestamp
    let current_time = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
    let state_ttl = current_time + 300;

    // store hashed state with corresponding code_verifier in dynamodb with ttl
    clients.dynamodb_client.put_item()
        .table_name(env::var("DynamoDbStateTable").expect("DynamoDbStateTable not set in env."))
        .item("state", AttributeValue::S(state_hash))
        .item("code_verifier", AttributeValue::S(code_verifier.to_string()))
        .item("ttl", AttributeValue::N(state_ttl.to_string()))
        .send()
        .await?;

    // craft authorize url to the IdP with adjusted query string params
    let idp_redirect = Url::parse_with_params(&env::var("IdpAuthUri").expect("IdpAuthUri not set in env."),
        &[
            ("scope", original_params.first("scope").unwrap()),
            ("state", original_params.first("state").unwrap()),
            ("redirect_uri", &env::var("ProxyCallbackUri").expect("ProxyCallbackUri not set in env")),
            ("client_id", original_params.first("client_id").unwrap()),
            ("response_type", original_params.first("response_type").unwrap()),
            ("code_challenge", &code_challenge_base64),
            ("code_challenge_method", "S256"),
        ]
    ).unwrap();

    let resp = Response::builder()
        .status(302)
        .header("Location", idp_redirect.as_str())
        .body("".into())
        .map_err(Box::new)?;
    Ok(resp)
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    tracing::init_default_subscriber();

    // initialize aws config
    let config = aws_config::defaults(BehaviorVersion::latest()).load().await;
    let shared_clients = Clients {
        sm_client: secretsmanager::Client::new(&config),
        dynamodb_client: dynamodb::Client::new(&config),
    };

    let func = service_fn(move |event| {
        let clients_ref = shared_clients.clone();
        async move { function_handler(&clients_ref, event).await }
    });

    run(func).await?;
    Ok(())
}
