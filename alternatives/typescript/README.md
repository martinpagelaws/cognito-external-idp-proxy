# Typescript deployment option

In this directory, you can find the same solution as in the root of the repository. However, the CDK stack is defined with typescript. For architecure details, see README.md in the root of this repository.

## Deployment

-   use node18 or higher
-   copy cdk.context.template to cdk.context.json and populate with your environment and IdP specifics
-   run `$ npx cdk deploy`
