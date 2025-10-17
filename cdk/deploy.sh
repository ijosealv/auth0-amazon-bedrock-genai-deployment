#!/bin/bash

# Bedrock Workshop CDK Deployment Script
# This script handles the complete deployment process

set -e  # Exit on any error

echo "🚀 Starting Bedrock Workshop CDK Deployment"
echo "============================================="

# Check prerequisites
echo "📋 Checking prerequisites..."

# Check Node.js
if ! command -v node &> /dev/null; then
    echo "❌ Node.js is not installed. Please install Node.js 18+ first."
    exit 1
fi

# Check AWS CLI
if ! command -v aws &> /dev/null; then
    echo "❌ AWS CLI is not installed. Please install and configure AWS CLI first."
    exit 1
fi

# Check CDK CLI
if ! command -v cdk &> /dev/null; then
    echo "❌ CDK CLI is not installed. Installing now..."
    npm install -g aws-cdk
fi

echo "✅ Prerequisites check passed"

# Install dependencies
echo "📦 Installing CDK dependencies..."
npm install

# Bootstrap CDK (if needed)
echo "🏗️ Checking CDK bootstrap status..."
if ! aws cloudformation describe-stacks --stack-name CDKToolkit &> /dev/null; then
    echo "🔧 Bootstrapping CDK..."
    cdk bootstrap
else
    echo "✅ CDK already bootstrapped"
fi

# Synthesize template
echo "🔨 Synthesizing CDK template..."
cdk synth

# Show differences
echo "📊 Showing deployment differences..."
cdk diff

# Deploy
echo "🚀 Deploying stack..."
read -p "Do you want to proceed with deployment? (y/N): " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    cdk deploy --require-approval never
    echo "✅ Deployment completed successfully!"
    
    # Show outputs
    echo "📋 Stack Outputs:"
    aws cloudformation describe-stacks --stack-name BedrockWorkshopStack --query 'Stacks[0].Outputs' --output table
else
    echo "❌ Deployment cancelled"
    exit 1
fi

echo "🎉 CDK deployment process completed!"