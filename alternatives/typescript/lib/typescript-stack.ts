import * as cdk from 'aws-cdk-lib/core';
import { Construct } from 'constructs';
import { NagSuppressions } from 'cdk-nag';

import * as apigw from 'aws-cdk-lib/aws-apigatewayv2';
import { HttpLambdaIntegration } from 'aws-cdk-lib/aws-apigatewayv2-integrations';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import { RetentionDays } from "aws-cdk-lib/aws-logs";

export class TypescriptStack extends cdk.Stack {
    private readonly apiGw: apigw.HttpApi;
    private readonly authnFnExecRole: iam.Role;
    private readonly callbFnExecRole: iam.Role;
    private readonly tokenFnExecRole: iam.Role;
    private readonly authnFnDynamoDbPolicy: iam.Policy;
    private readonly authnFnSecretsManagerPolicy: iam.Policy;
    private readonly authnIntegration: HttpLambdaIntegration;
    private readonly authnFn: lambda.Function;
    private readonly callbFn: lambda.Function;
    private readonly tokenFn: lambda.Function;
    private readonly dynamoDbStateTable: dynamodb.Table; 

    constructor(scope: Construct, id: string, props?: cdk.StackProps) {
        super(scope, id, props);


        /*
        GLOBAL CONFIGURATION ITEMS
        */

        // API GATEWAY
        const apiVersion = this.node.tryGetContext('api_version');
        const authnRoute = this.node.tryGetContext('api_authn_route');
        const callbRoute = this.node.tryGetContext('api_callback_route');
        const tokenRoute = this.node.tryGetContext('api_token_route');

        // LAMBDA AND ENV VARS
        const lambdaRuntime = this.node.tryGetContext('lambda_runtime');
        const allowedRuntimes: Array<string> = ['python', 'rust'];
        const idpClientId = this.node.tryGetContext('idp_client_id');
        const idpClientSecret = this.node.tryGetContext('idp_client_secret');
        const idpAuthUri = this.node.tryGetContext('idp_issuer_url') + this.node.tryGetContext('idp_auth_path');


        /*
        RESOURCE DEFINITIONS
        */

        // Empty Lambda Execution roles to later populate them with relevant statements
        this.authnFnExecRole = this.createFnExecRole('Authorization');
        this.callbFnExecRole = this.createFnExecRole('Callback');
        this.tokenFnExecRole = this.createFnExecRole('Token');

        // Deploy lambdas with the selected runtime
        switch ( lambdaRuntime ) {
            case 'python': {
                console.info('Deploying Python Lambdas');
                this.authnFn = this.createFnPython('Authorization', this.authnFnExecRole);
                this.callbFn = this.createFnPython('Callback', this.callbFnExecRole);
                this.tokenFn = this.createFnPython('Token', this.tokenFnExecRole);
                break;
            }
            case 'rust': {
                console.error('Rust runtime not yet implemented');
                process.exit(1);
            }
            default:
                console.error('Unsupported runtime defined in cdk.context.json lambda_runtime. Use: ' + allowedRuntimes.toString().replace(/,/g, " or "));
                process.exit(1);
        }

        this.authnFn.addEnvironment('ClientId', idpClientId);
        this.authnFn.addEnvironment('IdpAuthUri', idpAuthUri);

        // add a Dynamod DB table to store state information
        this.dynamoDbStateTable = this.createDynamoDbStateTable();
        this.authnFn.addEnvironment('DynamoDbStateTable', this.dynamoDbStateTable.tableName);

        // Grant least privilege permissions to auth function for state table and secretsmanager
        this.authnFnDynamoDbPolicy = this.createAuthnFnDynamoDbPolicy();
        this.authnFn.role?.attachInlinePolicy(this.authnFnDynamoDbPolicy);

        this.authnFnSecretsManagerPolicy = this.createAuthnFnSecretsManagerPolicy();
        this.authnFn.role?.attachInlinePolicy(this.authnFnSecretsManagerPolicy);

        // add an API Gateway
        this.apiGw = this.createApiGw();
        this.authnFn.addEnvironment('ProxyCallbackUri', this.apiGw.apiEndpoint + "/" + apiVersion + callbRoute);


        /*
        CDK NAG SUPPRESSION RULES
        */

        NagSuppressions.addResourceSuppressions(
            this.authnFnSecretsManagerPolicy, [
                { id: 'AwsSolutions-IAM5', reason: 'API is resource agnostic but resource key required in statement.' },
            ]
        );

        NagSuppressions.addResourceSuppressionsByPath(
            this, this.stackName + '/LogRetentionaae0aa3c5b4d4f87b02d85b201efdd8a/ServiceRole/Resource',
            [
                { id: 'AwsSolutions-IAM4', reason: 'Construct specific: Enabling log retention creates a separate Lambda Function with managed policy.' },
            ]
        )

        NagSuppressions.addResourceSuppressionsByPath(
            this, this.stackName + '/LogRetentionaae0aa3c5b4d4f87b02d85b201efdd8a/ServiceRole/DefaultPolicy/Resource',
            [
                { id: 'AwsSolutions-IAM5', reason: 'Construct specific: Enabling log retention creates a separate Lambda Function with managed policy.' },
            ]
        )

        NagSuppressions.addResourceSuppressions(
            this.authnFn,
            [
                { id: 'AwsSolutions-L1', reason: 'No tests in place to guarantee code runs in other versions.' }
            ]
        )

        NagSuppressions.addResourceSuppressions(
            this.callbFn,
            [
                { id: 'AwsSolutions-L1', reason: 'No tests in place to guarantee code runs in other versions.' }
            ]
        )

        NagSuppressions.addResourceSuppressions(
            this.tokenFn,
            [
                { id: 'AwsSolutions-L1', reason: 'No tests in place to guarantee code runs in other versions.' }
            ]
        )

        NagSuppressions.addResourceSuppressions(
            this.dynamoDbStateTable,
            [
                { id: 'AwsSolutions-DDB3', reason: 'Short lived data only.' }
            ]
        )

    }

    private createApiGw(): apigw.HttpApi {
        return new apigw.HttpApi(this, 'ApiGateway', {
            description: 'Handles requests and responses between Cognito and 3rd party IdP',
            createDefaultStage: false,
        });        
    }

    private createFnExecRole(n: string): iam.Role {
        return new iam.Role(this, n + 'FunctionExecRole', {
            assumedBy: new iam.ServicePrincipal('lambda.amazonaws.com'),
        });
    }

    private createAuthnFnPython(executionRole: iam.Role): lambda.Function {
        return new lambda.Function (this, 'AuthorizationFunction', {
            code: lambda.Code.fromAsset('./lambda/python/authorize'),
            handler: 'authorize_flow.handler',
            logRetention: RetentionDays.FIVE_DAYS,
            role: executionRole,
            runtime: lambda.Runtime.PYTHON_3_10,
        });
    }

    private createCallbFnPython(executionRole: iam.Role): lambda.Function {
        return new lambda.Function (this, 'CallbackFunction', {
            code: lambda.Code.fromAsset('./lambda/python/callback'),
            handler: 'callback_flow.handler',
            logRetention: RetentionDays.FIVE_DAYS,
            role: executionRole,
            runtime: lambda.Runtime.PYTHON_3_10,
        });
    }

    private createTokenFnPython(executionRole: iam.Role): lambda.Function {
        return new lambda.Function (this, 'TokenFunction', {
            code: lambda.Code.fromAsset('./lambda/python/token'),
            handler: 'token_flow.handler',
            logRetention: RetentionDays.FIVE_DAYS,
            role: executionRole,
            runtime: lambda.Runtime.PYTHON_3_10,
        });
    }

    private createFnPython(n: string, executionRole: iam.Role): lambda.Function {
        return new lambda.Function (this, n + 'Function', {
            code: lambda.Code.fromAsset('./lambda/python/' + n.toLowerCase()),
            handler: n.toLowerCase() + '_flow.handler',
            logRetention: RetentionDays.FIVE_DAYS,
            role: executionRole,
            runtime: lambda.Runtime.PYTHON_3_10,
        });
    }

    private createAuthnFnDynamoDbPolicy(): iam.Policy {
        return new iam.Policy(this, 'DynamoDbPolicy', {
            statements: [new iam.PolicyStatement({
                actions: ['dynamodb:DescribeTable', 'dynamodb:PutItem'],
                resources: [this.dynamoDbStateTable.tableArn],
            })],
        });
    }

    private createAuthnFnSecretsManagerPolicy(): iam.Policy {
        return new iam.Policy(this, 'SecretsManagerPolicy', {
            statements: [new iam.PolicyStatement({
                actions: ['secresmanager:GetRandomPassword'],
                resources: ['*'],
            })],
        });
    }

    private createDynamoDbStateTable(): dynamodb.Table {
        return new dynamodb.Table (this, 'StateTable', {
            partitionKey: {
                name: 'state',
                type: dynamodb.AttributeType.STRING,
            },
            billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
            timeToLiveAttribute: 'ttl',
        });
    }


}
