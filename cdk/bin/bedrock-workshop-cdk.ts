#!/usr/bin/env node
import 'source-map-support/register';
import * as cdk from 'aws-cdk-lib';
import { BedrockWorkshopStack } from '../lib/bedrock-workshop-stack';

const app = new cdk.App();

new BedrockWorkshopStack(app, 'BedrockWorkshopStack', {
  env: {
    account: process.env.CDK_DEFAULT_ACCOUNT,
    region: process.env.CDK_DEFAULT_REGION || 'us-east-1',
  },
  description: 'AWS CDK stack for Bedrock Workshop with Auth0 integration'
});