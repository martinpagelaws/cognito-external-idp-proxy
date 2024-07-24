use aws_config::{self, BehaviorVersion};
use aws_sdk_dynamodb::{self as dynamodb, types::AttributeValue};
use std::{env, time::SystemTime};
use lambda_http::{run, service_fn, tracing, Body, Error, Request, RequestExt, Response};
use url::Url;
use sha2::{Sha256, Digest};

async fn function_handler(event: Request) -> Result<Response<Body>, Error> {
    let original_params = event.query_string_parameters_ref().unwrap();
    let original_state = original_params.first("state").unwrap();
    let original_code = original_params.first("code").unwrap();


    // initialize aws config
    let config = aws_config::defaults(BehaviorVersion::latest()).load().await;
    let dynamodb_client = dynamodb::Client::new(&config);

    // get code_verifier from state_table with hashed state
    let mut state_hasher = Sha256::new();
    state_hasher.update(original_state.as_bytes());
    let state_hash = format!("{:x}", state_hasher.finalize());

    let dynamodb_query = dynamodb_client.get_item()
        .table_name(&env::var("DynamoDbStateTable").expect("DynamoDbStateTable not set in env."))
        .key("state", AttributeValue::S(state_hash))
        .attributes_to_get("code_verifier")
        .send()
        .await?;

    let code_verifier: String = dynamodb_query.item().unwrap().get("code_verifier").unwrap().as_s().unwrap().to_string();

    // store auth_code and code_verifier in auth_code_table with ttl
    let current_time = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs();
    let code_ttl = current_time + 300;
    dynamodb_client.put_item()
        .table_name(env::var("DynamoDbCodeTable").expect("DynamoDbCodeTable not set in env."))
        .item("auth_code", AttributeValue::S(original_code.to_string()))
        .item("code_verifier", AttributeValue::S(code_verifier))
        .item("ttl", AttributeValue::N(code_ttl.to_string()))
        .send()
        .await?;

    // craft redirect uri to Cognito IDP response endpoint
    let cognito_idp_response = Url::parse_with_params(&env::var("CognitoIdpResponseUri").expect("CognitoIdpResponseUri not set in env."),
        &[
            ("state", original_state), 
            ("code", original_code),
        ]
    ).unwrap();

    let resp = Response::builder()
        .status(302)
        .header("Location", cognito_idp_response.as_str())
        .body("".into())
        .map_err(Box::new)?;
    Ok(resp)
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    tracing::init_default_subscriber();

    run(service_fn(function_handler)).await
}
