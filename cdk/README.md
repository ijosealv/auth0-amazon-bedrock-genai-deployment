# Secure Amazon Bedrock Agent Application with Auth0

## Description

Deploy an Amazon Bedrock Agent chat application that uses Auth0 for user login and fine-grained access control. You'll set up authentication, configure user permissions, and deploy a Bedrock AI agent that perfoms actions based on each user's permission level. 

In this use case, authenticated users will be able to interact with the deployed AI Agent to perform IT Admin tasks such as:
- Reset User Passwords in Okta
- Retrieve user group information from Okta

The AI Agent will verify user permissions before executing any administrative actions, ensuring only authorized personnel can execute sensitive IT operations.

## Architecture

![Arch](/images/description/Architecture.png)

This workshop demonstrates how to build a secure AI-powered IT administration tool using Flask for the web interface, Auth0 for authentication/permissions, and Amazon Bedrock for AI agent capabilities.

## Platform Overview

This tutorial integrates four key platforms to create a secure, AI-powered IT administration solution:

### **Okta**
Enterprise identity and access management platform that serves as the source of truth for user identities and group memberships. In this tutorial, Okta manages user accounts, groups, and provides APIs for administrative operations like password resets and user group retrieval.

### **Auth0**
Customer identity and access management platform that handles authentication flows and user sessions. Auth0 acts as the authentication gateway, connecting to Okta via OpenID Connect (OIDC) and managing secure user login sessions for the web application.

### **Auth0 FGA (Fine-Grained Authorization)**
Authorization service that provides relationship-based access control using Fine-grained authorization models. FGA determines what actions users can perform based on their relationships and permissions, ensuring only authorized users can execute sensitive IT operations.

### **AWS (Amazon Web Services)**
Cloud platform hosting the entire application infrastructure including:
- **Amazon Bedrock Agents** - AI service powering the conversational interface
- **AWS Lambda** - Serverless compute for application logic and integrations
- **Amazon DynamoDB** - Session storage and state management
- **API Gateway** - Web application hosting and routing
- **AWS Secrets Manager** - Secure credential and key storage

## AWS Resources

| Resource | Purpose |
|----------|---------|
| **LLM model** | Amazon Nova Pro |
| **Amazon Bedrock Agent** | AI-powered conversational agent that processes user requests and routes them to appropriate action groups |
| **Amazon Bedrock Agent Alias** | Production-ready endpoint for the Bedrock agent with versioning support |
| **Bedrock Action Groups** | |
| - **CIBAAuthentication** | Handles elevated operations requiring additional authentication (password resets, user management) |
| - **OktaOperations** | Manages standard Okta operations like retrieving user groups and basic user information |
| **IAM Roles & Policies** | Secure access permissions for all Lambda functions and Bedrock agent interactions |
| **DynamoDB Table** | Stores encrypted user session data with TTL for automatic cleanup |
| **AWS Secrets Manager** | Securely stores Fernet encryption keys for session token encryption |
| **API Gateway** | REST API endpoint that serves the Flask web application |
| **Lambda Functions** | |
| - **bedrock-web-app** | Flask web application handling user authentication and chat interface |
| - **ciba-flow-lambda** | Manages CIBA (Client Initiated Backchannel Authentication) flows for elevated operations |
| - **fga-check-lambda** | Validates user permissions using Auth0 Fine-Grained Authorization |
| - **okta-token-lambda** | Handles Okta API operations and user group retrieval |
| - **fernet-key-generator** | Custom resource Lambda that generates secure encryption keys during deployment |

## Deployment steps

### Prerequisites

Before starting this tutorial, ensure you have access to the following accounts and tools:

#### **Required Accounts**
1. **Okta Account** 
2. **Auth0 Account**
3. **Auth0 FGA Account** 
4. **AWS Account** 

#### **Required Tools**
- **AWS CLI** - Configured with appropriate CLI credentials and default region
- **Node.js** (v18 or later) - For running AWS CDK
- **Auth0 Guardian MFA app** - Install Auth0 Guardian MFA app on Mobile Device

## Setup Okta Account

**For this Workshop make sure you use the default 'api://default' API Authorization Server**
**Admin Console -> Security -> API -> Authorization Servers**

### Create a test user and test group in Okta
1. Sign into **Okta Admin Console** (https://www.okta.com)
2. Navigate to **Directory -> People**
3. Click **Add Person** button
4. Fill in required fields:
   - First Name:
   - Last Name:
   - Username/Email:
   - Set password options according to your preference
5. Click **Save**
6. Navigate to **Directory -> Groups**
7. Click **Add Group**
8. Enter group details:
   - Name: TestGroup
   - Description: Group for Auth0 OIDC Connection
9. Click **Save**
10. From the Groups list, select your newly created **TestGroup**
11. Click **Assign People**
12. Search for your test user and click **Assign** next to their name
13. Verify the user appears in the group members list

### Create Application for OIDC Connection
1. Navigate to **Applications -> Applications -> Create App Integration**
2. Select **OIDC - OpenID Connect** for Sign-in method
3. Select **Web Application** for Application type
4. Click **Next**
5. Enter a name for your OIDC Connection
6. In **Controlled access** select **Limit access to selected groups** and choose the **TestGroup**
7. Click **Save**

![group](/images/okta/group.png)

### Edit Application for OIDC Connection
1. After creating your application, click on the application name to view its details
2. Navigate to the **General** tab
3. Under **General Settings**, click **Edit**
4. Scroll down to the **Grant type** section 
5. Under **Core grants**, enable **Refresh Token**
6. Scroll to **Refresh token** section
7. Configure refresh token settings:
    - Enable **Rotate token after every use**
    - Set **Grace period for token rotation** to **60 seconds**
8. Navigate to the **User consent**, select **Require consent**

![refresh](/images/okta/refresh.png)

9. Navigate to **LOGIN** and configure the following settings:
   - **Sign-in redirect URIs:**: Add your Auth0 tenant callback URL (e.g., `https://xxxxxxxx.us.auth0.com/login/callback`)
   - **Initiate login URI:**: Enter your Auth0 tenant login URL (e.g., `https://xxxxxxxxx.us.auth0.com/login`)
   - **Login initiated by:**: Select **Either Okta or App**
   - **Login flow:**: Select **Redirect to app to initiate login (OIDC Compliant)**
11. Click **Save** at the bottom of the page

![loginurl](/images/okta/loginurl.png)

12. Navigate to the **Okta API Scopes** tab
13. Click **Grant** for the following scopes:
    - **okta.users.read**
    - **okta.users.read.self**
    - **okta.groups.read**
    - **okta.apps.read**
    - **okta.users.manage**
    - **okta.users.manage.self**
    - **okta.userTypes.read** 
    - **okta.groups.manage**

![scopes](/images/okta/scopes.png)

### Copy Okta Application Credentials
1. Navigate back to the **General** tab of your Okta application
2. Copy the following values and save them in a notepad as you'll need them for Auth0 configuration:
   - **Client ID**: Copy the Client ID value
   - **Client Secret**: Copy the Client Secret value

![secrets](/images/okta/secrets.png)

**Important**: Keep these credentials secure and readily available as you'll use them in the next section to configure the Auth0 OIDC connection.

## Setup Auth0 Account

### Create Flask Web Application

1. Log into your GenAI Auth0 tenant (https://www.auth0.com)
2. Navigate to **Applications** on the left pane. 
3. Click **+Create Application** then provide a name **Bedrock Flask App** and select **Regular Web application** in the create application dialog and click **Create**

![app](/images/auth0/app.png)

4. Under **What technology are you using for your project?** choose **Python** 
5. Click the **Settings**
6. Copy the following values into a notepad as you will paste these vales in `config/environment.json` under `auth0` in the **Deploy the AWS Infrastructure using CDK** section
   - **ClientID**
   - **Client Secret**
   - **Domain value** 

![settings](/images/auth0/settings.png)

7. Scroll to the very bottom of the screen to **Advanced Settings** and click the **Grant Types** tab. In here, make sure **Token Exchange** and **CIBA** checkboxes are checked.
8. Click **Save**

![grants](/images/auth0/grants.png)

You have successfully created a Flask application in Auth0 with the necessary grant types configured. This application will serve as the foundation for integrating with Amazon Bedrock.

### Configure OIDC Okta Connection in Auth0
1. In the left navigation panel, under **Authentication** section and click **Enterprise**
2. Under **Custom Connections** click on **OpenID Connect**
3. Click **Create Connection**
4. Fill in the connection details:
   - **Connection name**: Enter a descriptive name (e.g., "Okta-OIDC")
   - **Issuer URL**: Enter your Okta OpenID configuration URL 
     (e.g., `https://xxxxxxxxxx.okta.com/.well-known/openid-configuration`)
   - **Client ID**: Paste the Client ID from section **Copy Okta Application Credentials**
   - **Client Secret**: Paste the Client Secret from section **Copy Okta Application Credentials**
   - Enable the **Enable Token Vault** option.

![openid](/images/auth0/openid.png)

![tokenv](/images/auth0/tokenv.png)

5. Click **Create**
6. In your OpenID Connection go to the **Settings** tab 
7. Under the **General** section, add the following in **Scopes**:
   - **offline_access** (for refresh tokens)
   - **okta.users.read** (for user information access)

![scope](/images/auth0/scope.png)

8. Click **Save Changes**
9. Select the **Login Experience** tab in the OIDC connection
10. Check the box named **Display connection as a button**
11. Click **Save**
   
![login1](/images/auth0/login.png)

12. Select the **Applications** tab in the OIDC connection
13. Enable the **Bedrock Flask App** option.

![enable](/images/auth0/enable.png)

You have successfully configured the OIDC Okta connection with the necessary scopes and token vault enabled, and linked it to your Bedrock Flask App. This establishes the authentication bridge between Auth0 and Okta for secure user authentication workflows.

### Enable Guardian App MFA

1. Navigate to your Auth0 FGA account (https://dashboard.fga.dev/)
2. On the left pane navigate to **Security** and click **Multi-Factor Auth**
2. Select **Push Notification using Auth0 Guardian** option

![mfa](/images/auth0/mfa.png)

3. Select **Push Notification using Auth0 Guardian** option
4. Verify that the **Push Notification using Auth0 Guardian** toggle is **enabled** (green)

![guard](/images/auth0/guard.png)

5. At the top left of the screen click **Back to Multi-factor Authentication**.
6. Scroll down to the **Require Multi-factor Auth** Section
7. Select the **Always option**
8. Click **Save**
9. If a pop up window appears, click **Continue**

![mfa1](/images/auth0/mfa1.png)

You have successfully configured Auth0 Guardian push notifications with mandatory multi-factor authentication. This setup enables secure CIBA authentication flows and ensures all users will be prompted to enroll in MFA during their first login attempt.

## Setup Auth0 FGA Account

### Configure FGA Authorization Model

1. In the **Auth0 FGA Console**, click on **Navigate to Model Explorer**

![edit](/images/fga/edit.png)

2. In the model editor, replace the current code with the following

```
model
  schema 1.1

type user

type group
  relations
    define member: [user]

type okta
  relations
    define read_okta: [user, group#member]
```

3. The preview map should change and look like the below image.
4. Click **Save** to save the authorization model

![model](/images/fga/model.png)

5. Navigate to the **Tuple Management** dashboard from the main dashboard.
6. Click **Add Tuple**.
7. Add a tuple representing that your user can read Okta groups, **add the following in fields**
- user: **ADD TEST OKTA USER EMAIL HERE**
- Object: okta: groups
- Relation: read_okta
8. Click **Add Tuple**

![tuples](/images/fga/tuples.png)

9. Next, click on the **Settings** on the left pane.
10. Under **Authorized Clients** Click **+ Create Client**.
11. Give the client a name and select all (4) check boxes
12. Click **Create**

![client](/images/fga/client.png)

13. Click **Continue**
14. Copy the following values into a notepad as you will paste these vales in `config/environment.json` under `fga` in the next section
- FGA_STORE_ID='xxxxxxxxxxxxxx'
- FGA_MODEL_ID='xxxxxxxxxxxxxxxx'
- FGA_CLIENT_ID='xxxxxxxxxxxxxxx'
- FGA_CLIENT_SECRET='xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx'

![creds](/images/fga/creds.png)

You have successfully configured the FGA authorization model with user relationships and created authorized client credentials. This establishes the fine-grained access control framework that your Amazon Bedrock agent will use to make authorization decisions.

## Setup AWS Account

### Deploy the AWS Infrastructure using CDK

1. **Clone the repository and navigate to the CDK directory:**
   ```bash
   git clone <repository-url>
   cd auth0-amazon-bedrock-genai-deployment/cdk
   ```

2. **Configure your environment variables:**
   - Edit `config/environment.json` with your values you copied from your Auth0 Application and FGA Client Credentials
   ```json
   {
     "auth0": {
       "domain": "your-domain.auth0.com",
       "clientId": "your_auth0_client_id",
       "clientSecret": "your_auth0_client_secret",
       "connectionName": "your_connection_name" //**example: Okta-OIDC**
     },
     "fga": {
       "clientId": "your_fga_client_id",
       "clientSecret": "your_fga_client_secret",
       "storeId": "your_fga_store_id",
       "modelId": "your_fga_model_id"
     },
     "okta": {
       "domain": "https://your-domain.okta.com"
     }
   }
   ```

3. **Install dependencies:**
   ```bash
   npm install
   ```

4. **Configure AWS CLI (if not already done):**
   ```bash
   aws configure
   # Enter your AWS Access Key ID, Secret Access Key, and default region
   ```

5. **Bootstrap CDK (first time only):**
   ```bash
   cdk bootstrap
   ```

6. **Deploy the stack:**
   ```bash
   cdk deploy
   ```
   - Review the resources that will be created
   - Type `y` to confirm deployment

7. **Deployment completion:**
   - The deployment will take approximately 2-3 minutes

This will deploy all AWS resources: 5 Lambda functions, Bedrock agent, DynamoDB table, Secrets Manager, and IAM roles.

### Configure Amazon Bedrock Agent
1. Navigate to the **Amazon Bedrock Console**
2. In the left navigation panel, scroll to the **Build** section and click **Agents**
3. Select the agent named **workshop-agent**

![agent](/images/bedrock/agent.png)

4. Click the orange **Edit in Agent Builder** button
5. Under **Select Model** click the small **pen icon** 

![pen](/images/bedrock/pen.png)

6. Under **Categories** select **Amazon**
7. Under **Models** select **Amazon Nova Pro**
8. Under **Inference** select **Inference profiles**, then select **US Nova Pro**
9. Click **Apply**

![profile](/images/bedrock/profile.png)

10. Click the **Additional settings** drop down
11. Under **User input** select **Enabled** option

![user](/images/bedrock/user.png)

12. Scroll to the top of the screen and click the orange **Save and exit** button.
13. Under **Prepare the Agent to test the latest changes.** click on the **Prepare** button

![prep](/images/bedrock/prep.png)

14. Scroll down to the **Alias** section in the Amazon Bedrock Agent Screen.
15. Select the current Alias and click the **Edit** button.

![alias](/images/bedrock/alias.png)

16. Under **Associate a version** select the **Create a new version and associate it to this alias** option.
17. Click **Save**

![save](/images/bedrock/save.png)

### Copy bedrock-web-app Callback URL
1. Navigate to the **AWS Lambda Console**
2. In the Lambda console select the **bedrock-web-app** Lambda
3. Select the **Configuration** tab
4. On the lefe pane select **Environment Variables**
5. Copy the **AUTH0_CALLBACK_URL** value as you will need this later.
- Example: of what to copy **https://xxxxxxx.execute-api.us-east-1.amazonaws.com/prod/callback**

![flask](/images/callback/flask.png)

### Configure Auth0 Application with API Gateway Callback URLs
1. Go back to your **Auth0 Console**
2. On the left pane click on **Applications**, and select the **Bedrock Flask App**

![flaskapp](/images/callback/flaskapp.png)

3. Click on the **Settings** Tab
4. Scroll down to **Application URIs** section
5. Using the link you copied in **Step 4** Paste the link in the following section
   - **Allowed Callback URLs**: https://xxxxxx.execute-api.us-east-1.amazonaws.com/prod/callback
   - **Application Login URI**: https://xxxxxxx.execute-api.us-east-1.amazonaws.com/prod/login
   - **Allowed Logout URLs**: https://xxxxxxx.execute-api.us-east-1.amazonaws.com/prod/logout

![url](/images/callback/url.png)

6. Make sure all 3 URLS match the picture above, except with your actual gateway link at the begining of the URLs.
7. Click **Save**

## Putting It All Together: Testing Your AI Agent

### Access the Web Application
1. Open a new **Private Browser Window**
2. Navigate to your login **API Gateway URL** from Lab 4 (Example: https://xxxxxxx.execute-api.us-east-1.amazonaws.com/prod/)
3. At the login screen, select the bottom option that says **Continue with 'Name of Connection'**

![log](/images/chat/log.png)

4. You will be redirected to an Okta login screen, enter the following credentials
- Username: Okta User
- Password: Okta User password

![okta](/images/chat/okta.png)

5. On your mobile device, please download the **Auth0 Guardian** app
6. Once downloaded, click **Continue**

![select](/images/chat/select.png)

7. Open the **Auth0 Guardian** App and on the top right click the **+Add** button
8. Select **Scan QR Code**
9. Using your mobile phone's camera through the Auth0 Guardian app, scan the QR code displayed on your computer screen to link your device with Auth0.
10. You will be redirected to the **Amazon Bedrock powered by Auth0** chatbot.

**Do not interact with the chatbot yet, please follow remaining steps**

### Disable MFA Policy
1. Open your **Auth0 Dashboard** window or tab.
2. On the left pane, under **Security** section, click on **Multi-factor Auth**
3. Scroll to **Require Multi-factor Auth**, change the MFA requirement to **Never**
4. Click **Save**
5. On the **Disabling MFA for all applications** screen click the red **Disable** button.

![disable](/images/chat/disable.png)

We're temporarily disabling MFA to focus on testing the FGA authorization and CIBA flows without MFA interference

### Interacting with the Amazon Bedrock AI Agent
1. Open a **New Private Browser Window**
2. Navigate to your login **API Gateway URL** from Lab 4 (Example: https://xxxxxxx.execute-api.us-east-1.amazonaws.com/prod/)
3. You should see a clean chatbot interface with, like the image below

![chatbot](/images/chat/chatbot.png)

We first want to test the Bedrock Action Group that retrieves Okta group information. This action group connects to an Okta environment to fetch user group memberships. The current user has admin rights and permissions configured through the FGA (Fine-Grained Authorization) console. This demonstrates both the Amazon Bedrock Action Group and the FGA authorization system working together.

4. Ask the chatbot: **What are the Okta groups for user 'youroktauser@mail.com'** (replace with your provided workshop user email)

![group](/images/chat/group.png)

The Bedrock agent successfully retrieved the user's Okta group memberships by calling the FGA Authorization Lambda function, which validated your permissions, then invoked the Okta Management Lambda function to query the Okta API.

5. Now ask the chatbot: **Reset password for user 'youroktauser@mail.com'** (replace with your provided workshop user email)
6. You will receive a notifcation on your mobile device from the **Auth0 Guardian** App.

<img src="/images/chat/phone.png" width="300" alt="Auth0 Guardian push notification on mobile device">

7. Open the notification and select **Approve** to approve the CIBA authentication request for the password reset operation.

![ciba](/images/chat/ciba.png)

When you requested the password reset, the Bedrock agent triggered the CIBA Authentication Lambda function, which initiated a backchannel authentication request through Auth0. This sent a push notification to your registered Guardian device for verification. By approving the request, you completed the CIBA flow, allowing the sensitive password reset operation to proceed. This demonstrates how CIBA adds an extra security layer for high-risk actions, ensuring that even authenticated users must provide additional verification for sensitive operations

### Removing FGA Tuple Permissions
1. Open your **FGA Dashboard** window or tab.
2. On the left pane click on **Tuple Management**
3. Locate the tuple that grants your user permission to read Okta groups (it should show your email, "read_okta" relation, and "okta groups" object) and click the small red trash icon to delete this tuple.
4. When promted click **Confirm** to delete tuple.

![tuple](/images/chat/tuple.png)

By removing this tuple, we've revoked the FGA permission that allowed your user to access Okta group information. This will demonstrate how fine-grained authorization works in real-time

5. Return to your web application window
6. Ask the chatbot the same question as before: **What are the Okta groups for user 'youroktauser@mail.com'** (replace with your provided workshop user email)
7. This time, you should receive an authorization denied message

![ask](/images/chat/ask.png)

The Bedrock agent attempted to call the FGA Authorization Lambda function to check your permissions, but since we deleted the tuple, the FGA system returned "not authorized." The agent respected this security decision and blocked the request, demonstrating how fine-grained authorization prevents unauthorized access in real-time

## Workshop Environment Clean-Up

### AWS Resources Cleanup

1. **Navigate to the CDK directory:**
   ```bash
   cd auth0-amazon-bedrock-genai-deployment/cdk
   ```

2. **Destroy the CDK stack:**
   ```bash
   cdk destroy
   ```
   - Type `y` to confirm deletion when prompted
   - Wait for the stack deletion to complete (typically 2-3 minutes)

3. **Verify cleanup:**
   - All AWS resources will be automatically removed by CDK
   - You can verify in the AWS Console that Lambda functions, DynamoDB table, and Bedrock agent have been removed
   - The CloudFormation stack created by CDK will also be deleted

4. **Optional: Clean up CDK bootstrap resources (only if no longer needed):**
   ```bash
   # Only run this if you won't be using CDK in this account/region anymore
   # This removes the CDK toolkit stack and S3 bucket
   aws cloudformation delete-stack --stack-name CDKToolkit
   ```

### Auth0 Resources
1. Optional: Delete the Auth0 application
   - Navigate to your Auth0 dashboard
   - Go to **Applications** → **Applications**
   - Select your workshop application
   - Scroll to the bottom and click **Delete Application**
   
2. Optional: Delete the OIDC connection
   - Go to **Authentication** → **Enterprise** → **OpenID Connect**
   - Find your Okta connection
   - Click the three dots menu (⋮) → **Delete**

### Auth0 FGA Account
- **No Charges**: The Auth0 FGA account you created is **free** and does not incur any charges under the free tier
- **Optional**: You may keep the FGA account active for future development, or you can disable the authorization store if preferred
- **To disable FGA store**: Navigate to your FGA dashboard → Settings → Store Settings → Disable Store

### Okta Resources
1. Optional: Delete the OIDC application
   - Navigate to your Okta admin console
   - Go to **Applications** → **Applications**
   - Find your OIDC application
   - Click **Delete** and confirm

### Auth0 Guardian App
- **Remove Workshop Account**: You can remove the workshop account from your Auth0 Guardian mobile app
- **To remove**: Open Auth0 Guardian app → Select the workshop account → Delete or remove account
- **Keep the App**: You may keep the Auth0 Guardian app installed for future use with other Auth0 applications
