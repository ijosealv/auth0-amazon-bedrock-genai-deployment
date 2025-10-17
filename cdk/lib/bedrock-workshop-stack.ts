import * as cdk from 'aws-cdk-lib';
import * as lambda from 'aws-cdk-lib/aws-lambda';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';
import * as secretsmanager from 'aws-cdk-lib/aws-secretsmanager';
import * as iam from 'aws-cdk-lib/aws-iam';
import * as apigateway from 'aws-cdk-lib/aws-apigateway';
import * as bedrock from 'aws-cdk-lib/aws-bedrock';
import { PythonFunction } from '@aws-cdk/aws-lambda-python-alpha';
import { Construct } from 'constructs';
import * as fs from 'fs';
import * as path from 'path';

export class BedrockWorkshopStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    // Load environment configuration
    const configPath = path.join(__dirname, '../config/environment.json');
    const config = JSON.parse(fs.readFileSync(configPath, 'utf8'));

    // ========================================
    // 1. FERNET KEY GENERATOR LAMBDA
    // ========================================

    // Lambda to generate proper Fernet encryption key
    const fernetKeyGenerator = new lambda.Function(this, 'FernetKeyGenerator', {
      functionName: 'fernet-key-generator-lambda',
      runtime: lambda.Runtime.PYTHON_3_12,
      handler: 'index.handler',
      code: lambda.Code.fromInline(`
import json
import base64
import secrets
import cfnresponse

def handler(event, context):
    try:
        if event['RequestType'] in ['Create', 'Update']:
            # Generate a proper Fernet key (32 random bytes, base64 encoded)
            key_bytes = secrets.token_bytes(32)
            fernet_key = base64.urlsafe_b64encode(key_bytes).decode('utf-8')
            
            response_data = {'FernetKey': fernet_key}
            cfnresponse.send(event, context, cfnresponse.SUCCESS, response_data, 'FernetKey')
        else:
            cfnresponse.send(event, context, cfnresponse.SUCCESS, {}, 'FernetKey')
    except Exception as e:
        print(f"Error: {str(e)}")
        cfnresponse.send(event, context, cfnresponse.FAILED, {}, 'FernetKey')
`),
      timeout: cdk.Duration.seconds(60),
    });

    // Custom resource to invoke the Fernet key generator
    const fernetKeyResource = new cdk.CustomResource(this, 'FernetKeyResource', {
      serviceToken: fernetKeyGenerator.functionArn,
    });

    // ========================================
    // 2. SECRETS MANAGER - Token Encryption
    // ========================================
    const tokenEncryptionSecret = new secretsmanager.Secret(this, 'TokenEncryptionSecret', {
      secretName: 'token-encryption-key',
      description: 'Fernet encryption key for session tokens in DynamoDB',
      secretStringValue: cdk.SecretValue.unsafePlainText(
        JSON.stringify({ key: fernetKeyResource.getAttString('FernetKey') })
      ),
    });

    // ========================================
    // 3. DYNAMODB TABLE - Session Storage
    // ========================================
    const sessionsTable = new dynamodb.Table(this, 'SessionsTable', {
      tableName: 'bedrock-sessions',
      partitionKey: {
        name: 'session_id',
        type: dynamodb.AttributeType.STRING,
      },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      timeToLiveAttribute: 'ttl',
      removalPolicy: cdk.RemovalPolicy.DESTROY, // For workshop - change for production
    });

    // ========================================
    // 4. LAMBDA FUNCTIONS
    // ========================================

    // CIBA Flow Lambda
    const cibaFlowLambda = new PythonFunction(this, 'CibaFlowLambda', {
      functionName: 'ciba-flow-lambda',
      entry: '../lambdas/ciba-flow-lambda',
      index: 'ciba.py', // Specify the main file
      handler: 'lambda_handler', // Just the function name
      runtime: lambda.Runtime.PYTHON_3_12,
      timeout: cdk.Duration.seconds(300),
      memorySize: 256,
      environment: {
        AUTH0_DOMAIN: config.auth0.domain,
        AUTH0_CLIENT_ID: config.auth0.clientId,
        AUTH0_CLIENT_SECRET: config.auth0.clientSecret,
        CIBA_BINDING_MESSAGE: '12345',
        CIBA_SCOPE: 'openid profile',
      },
    });

    // FGA Check Lambda
    const fgaCheckLambda = new PythonFunction(this, 'FgaCheckLambda', {
      functionName: 'fga-check-lambda',
      entry: '../lambdas/fga-check-lambda',
      index: 'fga_check.py',
      handler: 'lambda_handler',
      runtime: lambda.Runtime.PYTHON_3_12,
      timeout: cdk.Duration.seconds(30),
      memorySize: 256,
      environment: {
        FGA_API_ISSUER: 'fga.us.auth0.com',
        FGA_API_AUDIENCE: 'https://api.us1.fga.dev/',
        FGA_CLIENT_ID: config.fga.clientId,
        FGA_CLIENT_SECRET: config.fga.clientSecret,
        FGA_API_SCHEME: 'https',
        FGA_API_HOST: 'api.us1.fga.dev',
        FGA_STORE_ID: config.fga.storeId,
        FGA_MODEL_ID: config.fga.modelId,
      },
    });

    // Grant DynamoDB access to FGA Check Lambda
    sessionsTable.grantReadData(fgaCheckLambda);

    // Okta Token Lambda
    const oktaTokenLambda = new PythonFunction(this, 'OktaTokenLambda', {
      functionName: 'okta-token-lambda',
      entry: '../lambdas/okta-token-lambda',
      index: 'fga_tokenset.py',
      handler: 'lambda_handler',
      runtime: lambda.Runtime.PYTHON_3_12,
      timeout: cdk.Duration.seconds(60),
      memorySize: 512,
      environment: {
        SESSION_TABLE_NAME: sessionsTable.tableName,
        FGA_AUTHORIZER_FUNCTION_NAME: fgaCheckLambda.functionName,
        OKTA_DOMAIN: config.okta.domain,
        DEFAULT_OBJECT: 'okta:groups',
        DEFAULT_RELATION: 'read_okta',
        REQUEST_TIMEOUT: '30',
        MAX_RETRIES: '3',
        TOKEN_ENCRYPTION_SECRET_NAME: tokenEncryptionSecret.secretName,
      },
    });

    // Grant permissions to Okta Token Lambda
    sessionsTable.grantFullAccess(oktaTokenLambda);
    fgaCheckLambda.grantInvoke(oktaTokenLambda);
    tokenEncryptionSecret.grantRead(oktaTokenLambda);

    // Bedrock Web App Lambda
    const bedrockWebAppLambda = new PythonFunction(this, 'BedrockWebAppLambda', {
      functionName: 'bedrock-web-app',
      entry: '../lambdas/bedrock-web-app',
      index: 'lambda_function.py',
      handler: 'lambda_handler',
      runtime: lambda.Runtime.PYTHON_3_12,
      timeout: cdk.Duration.seconds(30),
      memorySize: 512,
    });

    // Grant permissions to Web App Lambda
    sessionsTable.grantFullAccess(bedrockWebAppLambda);
    tokenEncryptionSecret.grantRead(bedrockWebAppLambda);

    // ========================================
    // 5. BEDROCK AGENT
    // ========================================

    // IAM Role for Bedrock Agent
    const bedrockAgentRole = new iam.Role(this, 'BedrockAgentRole', {
      assumedBy: new iam.ServicePrincipal('bedrock.amazonaws.com'),
      managedPolicies: [
        iam.ManagedPolicy.fromAwsManagedPolicyName('AmazonBedrockFullAccess'),
      ],
      inlinePolicies: {
        BedrockAgentPolicy: new iam.PolicyDocument({
          statements: [
            new iam.PolicyStatement({
              effect: iam.Effect.ALLOW,
              actions: ['bedrock:*'],
              resources: ['*'],
            }),
            new iam.PolicyStatement({
              effect: iam.Effect.ALLOW,
              actions: ['lambda:InvokeFunction'],
              resources: [
                cibaFlowLambda.functionArn,
                fgaCheckLambda.functionArn,
                oktaTokenLambda.functionArn,
              ],
            }),
          ],
        }),
      },
    });

    // Bedrock Agent
    const bedrockAgent = new bedrock.CfnAgent(this, 'BedrockAgent', {
      agentName: 'workshop-agent',
      agentResourceRoleArn: bedrockAgentRole.roleArn,
      description: 'Bedrock agent powered by Amazon Nova',
      foundationModel: 'amazon.nova-pro-v1:0',
      idleSessionTtlInSeconds: 1800,
      instruction: 'This agent will use action groups to get user details and greet users when they say hi or hello. This agent will handle two sets of operations: one for retrieving Okta Groups for a user, and the agent will use the OktaOperations operation to process the request. The other operation would be the user performing an elevated operation, like resetting a password for an Okta user the agent will invoke the CIBAAuthentication action group.',
      actionGroups: [
        {
          actionGroupName: 'CIBAAuthentication',
          description: 'Action group for CIBA authentication',
          actionGroupExecutor: {
            lambda: cibaFlowLambda.functionArn,
          },
          functionSchema: {
            functions: [
              {
                name: 'authenticate_user',
                description: 'Use this action group when the user is trying to perform Delete a user, reset a password, or disable a user. Use this action group only when an elevated operations related to a user such as reset a password, disable the user',
                parameters: {
                  user_id: {
                    type: 'string',
                    description: 'User identifier for authentication',
                    required: true,
                  },
                },
              },
            ],
          },
        },
        {
          actionGroupName: 'OktaOperations',
          description: 'Action group for FGA tokenset operations and Okta group retrieval',
          actionGroupExecutor: {
            lambda: oktaTokenLambda.functionArn,
          },
          functionSchema: {
            functions: [
              {
                name: 'get_user_groups',
                description: 'Retrieve user groups from Okta using session-based authorization',
                parameters: {
                  user_email: {
                    type: 'string',
                    description: 'Email address of the user to retrieve groups for',
                    required: true,
                  },
                },
              },
            ],
          },
        },
      ],
    });

    // Bedrock Agent Alias
    const bedrockAgentAlias = new bedrock.CfnAgentAlias(this, 'BedrockAgentAlias', {
      agentId: bedrockAgent.attrAgentId,
      agentAliasName: 'WorkshopAlias',
      description: 'Production alias for Amazon Nova agent',
    });

    // ========================================
    // 6. API GATEWAY
    // ========================================

    const api = new apigateway.RestApi(this, 'BedrockWorkshopApi', {
      restApiName: 'FlaskBedrockAPI',
      description: 'API Gateway for Flask Bedrock application',
      endpointConfiguration: {
        types: [apigateway.EndpointType.REGIONAL],
      },
      deploy: false, // Disable automatic deployment to avoid circular dependency
    });

    // Lambda integration
    const lambdaIntegration = new apigateway.LambdaIntegration(bedrockWebAppLambda);

    // Add proxy resource
    const proxyResource = api.root.addResource('{proxy+}');
    const proxyMethod = proxyResource.addMethod('ANY', lambdaIntegration);
    const rootMethod = api.root.addMethod('ANY', lambdaIntegration);

    // Create deployment stage explicitly
    const deployment = new apigateway.Deployment(this, 'ApiDeployment', {
      api: api,
    });

    // Ensure deployment happens after methods are created
    deployment.node.addDependency(proxyMethod);
    deployment.node.addDependency(rootMethod);

    const stage = new apigateway.Stage(this, 'ApiStage', {
      deployment: deployment,
      stageName: 'prod',
    });

    // Construct the API URL manually to avoid circular dependency
    const apiUrl = `https://${api.restApiId}.execute-api.${this.region}.amazonaws.com/${stage.stageName}/`;

    // Set static environment variables
    bedrockWebAppLambda.addEnvironment('APP_SECRET_KEY', 'tJxc4s8mdmYQE5HbW9uAopTR5jLgN8qSWlGrkFIh6wA=');
    bedrockWebAppLambda.addEnvironment('AUTH0_CLIENT_ID', config.auth0.clientId);
    bedrockWebAppLambda.addEnvironment('AUTH0_CLIENT_SECRET', config.auth0.clientSecret);
    bedrockWebAppLambda.addEnvironment('AUTH0_DOMAIN', config.auth0.domain);
    bedrockWebAppLambda.addEnvironment('AUTH0_CONNECTION_NAME', config.auth0.connectionName);
    bedrockWebAppLambda.addEnvironment('SESSION_TABLE_NAME', sessionsTable.tableName);
    bedrockWebAppLambda.addEnvironment('TOKEN_ENCRYPTION_SECRET_NAME', tokenEncryptionSecret.secretName);
    bedrockWebAppLambda.addEnvironment('BEDROCK_AGENT_ID', bedrockAgent.attrAgentId);
    bedrockWebAppLambda.addEnvironment('BEDROCK_AGENT_ALIAS_ID', bedrockAgentAlias.attrAgentAliasId);

    // Add AUTH0_CALLBACK_URL using CloudFormation Fn::Sub to construct the URL
    const cfnLambda = bedrockWebAppLambda.node.defaultChild as lambda.CfnFunction;
    cfnLambda.addPropertyOverride('Environment.Variables.AUTH0_CALLBACK_URL',
      cdk.Fn.sub('https://${ApiId}.execute-api.${AWS::Region}.amazonaws.com/prod/callback', {
        ApiId: api.restApiId
      })
    );

    // Grant Bedrock permissions to Web App Lambda
    bedrockWebAppLambda.addToRolePolicy(new iam.PolicyStatement({
      effect: iam.Effect.ALLOW,
      actions: ['bedrock:InvokeAgent'],
      resources: ['*'],
    }));

    // ========================================
    // 7. LAMBDA PERMISSIONS
    // ========================================

    // Bedrock permissions to invoke Lambda functions
    cibaFlowLambda.addPermission('BedrockInvokePermission', {
      principal: new iam.ServicePrincipal('bedrock.amazonaws.com'),
      sourceArn: `arn:aws:bedrock:${this.region}:${this.account}:agent/*`,
    });

    fgaCheckLambda.addPermission('BedrockInvokePermission', {
      principal: new iam.ServicePrincipal('bedrock.amazonaws.com'),
      sourceArn: `arn:aws:bedrock:${this.region}:${this.account}:agent/*`,
    });

    oktaTokenLambda.addPermission('BedrockInvokePermission', {
      principal: new iam.ServicePrincipal('bedrock.amazonaws.com'),
      sourceArn: `arn:aws:bedrock:${this.region}:${this.account}:agent/*`,
    });

    // ========================================
    // 8. OUTPUTS
    // ========================================

    new cdk.CfnOutput(this, 'BedrockAgentId', {
      value: bedrockAgent.attrAgentId,
      description: 'ID of the created Bedrock Agent',
    });

    new cdk.CfnOutput(this, 'BedrockAgentAliasId', {
      value: bedrockAgentAlias.attrAgentAliasId,
      description: 'ID of the created Bedrock Agent Alias',
    });

    new cdk.CfnOutput(this, 'DynamoDBTableName', {
      value: sessionsTable.tableName,
      description: 'Name of the DynamoDB table for session management',
    });

    new cdk.CfnOutput(this, 'ApiGatewayUrl', {
      value: apiUrl,
      description: 'URL of the Flask application via API Gateway',
    });

    new cdk.CfnOutput(this, 'TokenEncryptionSecretName', {
      value: tokenEncryptionSecret.secretName,
      description: 'Name of the token encryption secret',
    });


  }
}