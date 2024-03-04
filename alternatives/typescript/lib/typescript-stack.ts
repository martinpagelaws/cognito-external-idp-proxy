import * as cdk from 'aws-cdk-lib/core';
import * as dotenv from 'dotenv';
import { Construct } from 'constructs';
import { NagSuppressions } from 'cdk-nag';

import * as apigw from 'aws-cdk-lib/aws-apigatewayv2';
import { HttpLambdaIntegration } from 'aws-cdk-lib/aws-apigatewayv2-integrations';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import { RetentionDays } from "aws-cdk-lib/aws-logs";

export class TypescriptStack extends cdk.Stack {
    private readonly authnFnExecRole: iam.Role;
    private readonly authnInt: HttpLambdaIntegration;
    private readonly authnFnPython: lambda.Function;

    constructor(scope: Construct, id: string, props?: cdk.StackProps) {
        super(scope, id, props);

        /*
        GLOBAL CONFIGURATION ITEMS
        */

        dotenv.config();

        const apiVersion = this.node.tryGetContext('api_version');
        const authnRoute = this.node.tryGetContext('api_authn_route');
        const callbRoute = this.node.tryGetContext('api_callback_route');
        const tokenRoute = this.node.tryGetContext('api_token_route');
        const lambdaRuntime = this.node.tryGetContext('lambda_runtime');

        const allowedRuntimes: Array<string> = ['python', 'rust'];


        /*
        RESOURCE DEFINITIONS
        */

        this.authnFnExecRole = this.createAuthnFnExecRole();
        switch ( lambdaRuntime ) {
            case 'python': {
                console.log('Deploying Python Lambdas');
                this.authnFnPython = this.createAuthnFnPython(this.authnFnExecRole);
                break;
            }
            case 'rust': {
                console.log('Rust runtime not yet implemented');
                process.exit(1);
            }
            default:
                console.log('Unsupported runtime defined in cdk.context.json lambda_runtime. Use: ' + allowedRuntimes);
                process.exit(1);
        }
        /* Not yet
        NagSuppressions.addResourceSuppressions(
            this.authnFnExecRole, [
                { id: 'AwsSolutions-IAM4', reason: 'Demo purposes only.' },
                { id: 'AwsSolutions-IAM5', reason: 'API is resource agnostic but resource key required in statement.' },
            ]
        );
        */

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
            this.authnFnPython,
            [
                { id: 'AwsSolutions-L1', reason: 'No tests in place to guarantee code runs in other versions.' }
            ]
        )
    }

    private createAuthnFnExecRole(): iam.Role {
        return new iam.Role(this, 'AuthorizationFunctionExecRole', {
            assumedBy: new iam.ServicePrincipal('lambda.amazonaws.com'),
            /*
            managedPolicies: [
                iam.ManagedPolicy.fromAwsManagedPolicyName('service-role/AWSLambdaBasixExecutionRole')
            ]
            */
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


}
