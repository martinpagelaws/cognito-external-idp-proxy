// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

import * as cdk from "aws-cdk-lib/core";
import { Construct } from "constructs";
import { NagSuppressions } from "cdk-nag";

import * as apigw from "aws-cdk-lib/aws-apigatewayv2";
import { HttpRoute } from "aws-cdk-lib/aws-apigatewayv2";
import { HttpLambdaIntegration } from "aws-cdk-lib/aws-apigatewayv2-integrations";
import * as cognito from "aws-cdk-lib/aws-cognito";
import * as dynamodb from "aws-cdk-lib/aws-dynamodb";
import * as iam from "aws-cdk-lib/aws-iam";
import * as lambda from "aws-cdk-lib/aws-lambda";
import * as logs from "aws-cdk-lib/aws-logs";
import * as secretsmanager from "aws-cdk-lib/aws-secretsmanager";
import { RetentionDays } from "aws-cdk-lib/aws-logs";

export class PkjwtStack extends cdk.Stack {
    private readonly apiGw: apigw.HttpApi;
    private readonly apiGwTokenRouteUri;
    private readonly apiGwStage: apigw.CfnStage;
    private readonly cognitoIdpResponseUri: string;
    private readonly cognitoOAuthScopes: Array<cognito.OAuthScope> = [];
    private readonly cognitoUserPool: cognito.UserPool;
    private readonly cognitoUserPoolClient: cognito.UserPoolClient;
    private readonly cognitoUserPoolDomain: cognito.UserPoolDomain;
    private readonly cognitoUserPoolIdpOidc: cognito.UserPoolIdentityProviderOidc;
    private readonly secretsManagerSecret: secretsmanager.Secret;
    private readonly tokenFn: lambda.Function;
    private readonly tokenFnExecRole: iam.Role;
    private readonly tokenFnDynamoDbPolicy: iam.Policy;
    private readonly tokenFnLayerVersion: lambda.LayerVersion;
    private readonly tokenFnSecretsManagerPolicy: iam.Policy;
    private readonly tokenIntegration: HttpLambdaIntegration;
    private readonly tokenIntegrationRoute: HttpRoute[];

    constructor(scope: Construct, id: string, props?: cdk.StackProps) {
        super(scope, id, props);

        // GLOBAL CONFIGURATION ITEMS

        // API GATEWAY
        const apiVersion = this.node.tryGetContext("api_version");
        const tokenRoute = this.node.tryGetContext("api_token_route");

        // LAMBDA AND ENV VARS
        const lambdaRuntime = this.node.tryGetContext("lambda_runtime");
        const allowedRuntimes: Array<string> = ["python", "rust"];
        const idpClientId = this.node.tryGetContext("idp_client_id");
        const idpClientSecret = this.node.tryGetContext("idp_client_secret");
        const idpIssuerUrl = this.node.tryGetContext("idp_issuer_url");
        const idpAuthUri = this.node.tryGetContext("idp_issuer_url") + this.node.tryGetContext("idp_auth_path");
        const idpTokenPath = this.node.tryGetContext("idp_token_path");
        const idpScopes = this.node.tryGetContext("idp_scopes");
        const idpKeysPath = this.node.tryGetContext("idp_keys_path");
        const idpAttributesPath = this.node.tryGetContext("idp_attributes_path");
        const idpName = this.node.tryGetContext("idp_name");
        const pkce = String(this.node.tryGetContext("pkce"));
        const idpAllowedCallbUrl = this.node.tryGetContext("userpool_allowed_callback_url");

        // RESOURCE DEFINITIONS

        // Empty Lambda Execution roles to later populate them with relevant statements
        this.tokenFnExecRole = this.createFnExecRole("Token");

        // Deploy lambdas with the selected runtime
        switch (lambdaRuntime) {
            case "python": {
                console.info("Deploying Python Lambdas");
                this.tokenFn = this.createFnPython("Token", this.tokenFnExecRole, 10);
                break;
            }
            case "rust": {
                console.error("Rust runtime not yet implemented");
                process.exit(1);
            }
            default:
                console.error(
                    "Unsupported runtime defined in cdk.context.json lambda_runtime. Use: " +
                        allowedRuntimes.toString().replace(/,/g, " or ")
                );
                process.exit(1);
        }

        // add 3rd party package layer to token function
        // $ python3.10 -m \
        //   pip install -r ./lambda/python/token/requirements.txt \
        //   --target ./layers/token/python \
        //   --only-binary=":all:" \
        //   --platform manylinux2014_x86_64
        this.tokenFnLayerVersion = this.createTokenFnLayerVersion();
        this.tokenFn.addLayers(this.tokenFnLayerVersion);

        // create an empty SecretsManager secret to hold the private key for private key JWT token requests
        this.secretsManagerSecret = new secretsmanager.Secret(this, "PrivateKey");

        // grant least privilege permissions to token function
        this.tokenFnSecretsManagerPolicy = this.createTokenFnSecretsManagerPolicy();
        this.tokenFn.role?.attachInlinePolicy(this.tokenFnSecretsManagerPolicy);

        // Create an API gateway with the required Lambda integrations
        this.apiGw = this.createApiGw();

        this.tokenIntegration = this.createIntegration("TokenIntegration", this.tokenFn);
        this.tokenIntegrationRoute = this.apiGw.addRoutes({
            path: tokenRoute,
            methods: [apigw.HttpMethod.POST],
            integration: this.tokenIntegration,
        });

        // create an API GW Stage / API version and compose the full urls for later reference
        this.apiGwStage = this.createApiGwStage(this.apiGw, apiVersion);
        this.apiGwTokenRouteUri = this.apiGw.apiEndpoint + "/" + apiVersion + tokenRoute;

        // create the Cognito User Pool and add an OIDC Identity Provider
        this.cognitoUserPool = this.createCognitoUserPool();
        this.cognitoUserPoolIdpOidc = new cognito.UserPoolIdentityProviderOidc(this, "UserPoolIdentityProviderOidc", {
            clientId: idpClientId,
            clientSecret: idpClientSecret,
            issuerUrl: idpIssuerUrl,
            userPool: this.cognitoUserPool,
            attributeRequestMethod: cognito.OidcAttributeRequestMethod.GET,
            endpoints: {
                authorization: idpAuthUri,
                jwksUri: idpIssuerUrl + idpKeysPath,
                token: this.apiGwTokenRouteUri,
                userInfo: idpIssuerUrl + idpAttributesPath,
            },
            name: idpName,
            scopes: idpScopes.split(" "),
        });

        // match string scopes to cognito OAuthScope properties
        for (let scope of idpScopes.split(" ")) {
            // this.cognitoOAuthScopes.push(cognito.OAuthScope[scope as keyof cognito.OAuthScope]);
            switch (scope.toLowerCase()) {
                case "openid":
                    this.cognitoOAuthScopes.push(cognito.OAuthScope.OPENID);
                    break;
                case "email":
                    this.cognitoOAuthScopes.push(cognito.OAuthScope.EMAIL);
                    break;
                case "phone":
                    this.cognitoOAuthScopes.push(cognito.OAuthScope.PHONE);
                    break;
                case "profile":
                    this.cognitoOAuthScopes.push(cognito.OAuthScope.PROFILE);
                    break;
            }
        }

        // create the Cognito App Client to integrate with your application
        this.cognitoUserPoolClient = this.cognitoUserPool.addClient("UserPoolClient", {
            oAuth: {
                flows: {
                    authorizationCodeGrant: true,
                },
                scopes: this.cognitoOAuthScopes,
                callbackUrls: [idpAllowedCallbUrl],
            },
            supportedIdentityProviders: [
                cognito.UserPoolClientIdentityProvider.custom(this.cognitoUserPoolIdpOidc.providerName),
            ],
        });

        // add domain to use the hosted ui - corresponds with the api gw id just to keep things simple here
        this.cognitoUserPoolDomain = this.cognitoUserPool.addDomain("UserPoolDomain", {
            cognitoDomain: {
                domainPrefix: this.apiGw.apiId,
            },
        });

        // compose the Cognito idp response URI for later reference
        this.cognitoIdpResponseUri =
            "https://" +
            this.cognitoUserPoolDomain.domainName +
            ".auth." +
            this.region +
            ".amazoncognito.com/oauth2/idpresponse";

        // populate functions with relevant environment variables
        this.tokenFn.addEnvironment("ClientId", idpClientId);
        this.tokenFn.addEnvironment("ClientSecret", idpClientSecret);
        this.tokenFn.addEnvironment("IdpIssuerUrl", idpIssuerUrl);
        this.tokenFn.addEnvironment("IdpTokenPath", idpTokenPath);
        this.tokenFn.addEnvironment("ResponseUri", this.cognitoIdpResponseUri);
        this.tokenFn.addEnvironment("Pkce", pkce);
        this.tokenFn.addEnvironment("Region", this.region);
        this.tokenFn.addEnvironment("SecretsManagerPrivateKey", this.secretsManagerSecret.secretName);

        // OUTPUTS
        new cdk.CfnOutput(this, "ApiGwTokenEndpoint", { value: this.apiGwTokenRouteUri });
        new cdk.CfnOutput(this, "SecretsManagerPrivateKeyArn", { value: this.secretsManagerSecret.secretArn });
        new cdk.CfnOutput(this, "CognitoIdpResponseUri", { value: this.cognitoIdpResponseUri });

        // CDK NAG SUPPRESSION RULES
        NagSuppressions.addResourceSuppressions(this.secretsManagerSecret, [
            {
                id: "AwsSolutions-SMG4",
                reason: "Cannot rotate due to 3rd party IdP dependency.",
            },
        ]);

        NagSuppressions.addResourceSuppressionsByPath(
            this,
            this.stackName + "/LogRetentionaae0aa3c5b4d4f87b02d85b201efdd8a/ServiceRole/Resource",
            [
                {
                    id: "AwsSolutions-IAM4",
                    reason: "Construct specific: Enabling log retention creates a separate Lambda Function with managed policy.",
                },
            ]
        );

        NagSuppressions.addResourceSuppressionsByPath(
            this,
            this.stackName + "/LogRetentionaae0aa3c5b4d4f87b02d85b201efdd8a/ServiceRole/DefaultPolicy/Resource",
            [
                {
                    id: "AwsSolutions-IAM5",
                    reason: "Construct specific: Enabling log retention creates a separate Lambda Function with managed policy.",
                },
            ]
        );

        NagSuppressions.addResourceSuppressions(this.tokenFn, [
            {
                id: "AwsSolutions-L1",
                reason: "No tests in place to guarantee code runs in other versions.",
            },
        ]);

        NagSuppressions.addResourceSuppressions(this.tokenIntegrationRoute, [
            { id: "AwsSolutions-APIG4", reason: "Demo purposes only." },
        ]);

        NagSuppressions.addResourceSuppressions(this.tokenFnExecRole, [
            { id: "AwsSolutions-IAM4", reason: "Demo purposes only." },
        ]);

        NagSuppressions.addResourceSuppressions(this.cognitoUserPool, [
            { id: "AwsSolutions-COG1", reason: "Demo is supposed to integrate only with external IdP." },
            { id: "AwsSolutions-COG2", reason: "Defined by external IdP." },
            { id: "AwsSolutions-COG3", reason: "Demo purposes only." },
        ]);
    }

    // RESOURCE CREATION FUNCTIONS

    private createApiGw(): apigw.HttpApi {
        return new apigw.HttpApi(this, "ApiGateway", {
            description: "Handles requests and responses between Cognito and 3rd party IdP",
            createDefaultStage: false,
        });
    }

    private createIntegration(name: string, fn: lambda.Function): HttpLambdaIntegration {
        return new HttpLambdaIntegration(name, fn);
    }

    private createFnExecRole(n: string): iam.Role {
        return new iam.Role(this, n + "FunctionExecRole", {
            assumedBy: new iam.ServicePrincipal("lambda.amazonaws.com"),
            managedPolicies: [iam.ManagedPolicy.fromAwsManagedPolicyName("service-role/AWSLambdaBasicExecutionRole")],
        });
    }

    private createFnPython(n: string, executionRole: iam.Role, timeOut?: number): lambda.Function {
        let timeOutDuration: number = 5;
        if (typeof timeOut !== "undefined") {
            timeOutDuration = timeOut;
        }

        return new lambda.Function(this, n + "Function", {
            code: lambda.Code.fromAsset("./lambda/python/" + n.toLowerCase()),
            handler: n.toLowerCase() + "_flow.handler",
            logRetention: RetentionDays.FIVE_DAYS,
            role: executionRole,
            runtime: lambda.Runtime.PYTHON_3_10,
            timeout: cdk.Duration.seconds(timeOutDuration),
        });
    }

    private createTokenFnSecretsManagerPolicy(): iam.Policy {
        return new iam.Policy(this, "tokenFnSecretsManagerPolicy", {
            statements: [
                new iam.PolicyStatement({
                    actions: ["secretsmanager:GetSecretValue"],
                    resources: [this.secretsManagerSecret.secretArn],
                }),
            ],
        });
    }

    private createApiGwStage(api: apigw.HttpApi, name: string): apigw.CfnStage {
        const logGroup = new logs.LogGroup(this, "ApiGwLogs");
        return new apigw.CfnStage(this, "ApiGwStage", {
            apiId: api.apiId,
            stageName: name,
            autoDeploy: true,
            accessLogSettings: {
                destinationArn: logGroup.logGroupArn,
                format: JSON.stringify({
                    requestId: "$context.requestId",
                    path: "$context.path",
                    routeKey: "$context.routeKey",
                    ip: "$context.identity.sourceIp",
                    requestTime: "$context.requestTime",
                    httpMethod: "$context.httpMethod",
                    statusCode: "$context.status",
                }),
            },
        });
    }

    private createCognitoUserPool(): cognito.UserPool {
        return new cognito.UserPool(this, "UserPool");
    }

    private createTokenFnLayerVersion(): lambda.LayerVersion {
        return new lambda.LayerVersion(this, "JwtPackageLayer", {
            code: lambda.Code.fromAsset("./layers/token/"),
            compatibleRuntimes: [lambda.Runtime.PYTHON_3_10],
            compatibleArchitectures: [lambda.Architecture.X86_64],
        });
    }
}
