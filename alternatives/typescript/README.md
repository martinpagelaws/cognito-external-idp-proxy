# Typescript deployment option

In this directory, you can find the same solution as in the root of the repository. However, the CDK stack is defined with typescript and you can set the Lambda functions to run the experimental Rust runtime.

## Deployment
* copy cdk.context.template to cdk.context.json and populate with your environment specifics


## Useful commands

* `npm run build`   compile typescript to js
* `npm run watch`   watch for changes and compile
* `npm run test`    perform the jest unit tests
* `npx cdk deploy`  deploy this stack to your default AWS account/region
* `npx cdk diff`    compare deployed stack with current state
* `npx cdk synth`   emits the synthesized CloudFormation template
