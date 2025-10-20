# Secure Amazon Bedrock Agent Application with Auth0

## Description

Deploy an Amazon Bedrock Agent chat application that uses Auth0 for user login and fine-grained access control. You'll set up authentication, configure user permissions, and deploy a Bedrock AI agent that performs actions based on each user's permission level. 

In this use case, authenticated users will be able to interact with the deployed AI Agent to perform IT Admin tasks such as:
- Reset User Passwords in Okta
- Retrieve user group information from Okta

The AI Agent will verify user permissions before executing any administrative actions, ensuring only authorized personnel can execute sensitive IT operations.

## Deployment Options

This project provides **two deployment methods**. Choose the one that best fits your needs:

### 🚀 Option 1: AWS CDK (Recommended)
- **Directory**: `/cdk`
- **Best for**: Developers familiar with Infrastructure as Code
- **Prerequisites**: Node.js, AWS CLI, CDK experience
- **Instructions**: See [CDK README](./cdk/README.md)

### 📋 Option 2: CloudFormation Template
- **Directory**: `/cloudformation` 
- **Best for**: Quick deployment without additional tooling
- **Prerequisites**: AWS Console access only
- **Instructions**: See [CloudFormation README](./cloudformation/README.md)
- **Required Manual Lambda deployment**: .zip files not included; requirmenets.txt in each lambda need to be ran on Amazon Linux with Python 3.12

## Architecture

![Arch](/images/description/Architecture.png)

This workshop demonstrates how to build a secure AI-powered IT administration tool using Flask for the web interface, Auth0 for authentication/permissions, and Amazon Bedrock for AI agent capabilities.
