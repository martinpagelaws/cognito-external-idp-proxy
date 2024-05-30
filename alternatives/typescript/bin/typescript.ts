#!/usr/bin/env node
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: MIT-0

import "source-map-support/register";
import * as cdk from "aws-cdk-lib";
import { PkjwtPkceStack } from "../lib/pkjwt-pkce";
import { PkjwtStack } from "../lib/pkjwt";

import { AwsSolutionsChecks } from "cdk-nag";
import { Aspects } from "aws-cdk-lib";

const app = new cdk.App();
Aspects.of(app).add(new AwsSolutionsChecks({ verbose: true }));

const stackName: string = app.node.tryGetContext("stack_name" || "CognitoProxyStack");

if (app.node.tryGetContext("pkce")) {
    console.info("Deploying stack with PKCE");
    new PkjwtPkceStack(app, stackName, {});
} else {
    console.info("Deploying stack without PKCE");
    new PkjwtStack(app, stackName, {});
}
