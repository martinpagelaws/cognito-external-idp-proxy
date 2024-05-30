# Typescript deployment option

In this directory, you can find the same solution as in the root of the repository. However, the CDK stack is defined with typescript. For architecure details, see README.md in the root of this repository.

## Deployment

-   use node18 or higher
-   copy cdk.context.template to cdk.context.json and populate with your environment and IdP specifics
-   validate before deployment with `$ npx cdk synth`
-   run `$ npx cdk deploy`
-   This solution deploys an empty AWS SecretsManager secret to hold the private key. Refer to root README.md section "Managing keys for Private Key JWT functionality".
-   If you use PKCE: add the callback endpoint URL to your IdP's allowed redirect / Sign-In URLs
-   If you do not use PKCE: add the Cognito IDP Response URI to your IdP's allowed redirect / Sign-in URLs
