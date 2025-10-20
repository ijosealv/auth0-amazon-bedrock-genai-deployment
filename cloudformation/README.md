# Deployment steps

## Prereqs

1. Have Okta OIDC Connection Setup with Auth0
2. Have Auth0 Flask Web Application setup
3. Have AUth0 Enterprise OIDC setup properly 
4. Have FGA setup

**MAKE SURE TO ONLY USE US-EAST-1 REGION**

### Step 1: Deploy the CloudFormation Template
Deploy the `auth0-bedrock-workshop-cfn.yml` CloudFormation template to create all AWS resources.

### Step 2: Request Nova Model Access
1. Open the :link[Amazon Bedrock console]{href="https://us-east-1.console.aws.amazon.com/bedrock/home?region=us-east-1#/"}
2. In the left navigation panel, scroll down to the **Configure and learn** section and click **Model access**

![access](/images/lab3/access.png)

3. Select the **Enable specific models** button

![enable](/images/lab3/enable.png)

4. Select the **Collapse all** button on the right side of the screen
5. Select the box for **Amazon** models
6. Click the **Next** button

![enable](/images/lab3/request.png)

7. In the review screen scroll down and click **Submit**

### Step 3: Configure Amazon Bedrock Agent
1. In the left navigation panel, scroll to the **Build** section and click **Agents**
2. Select the agent named **workshop-agent**

![agent](/images/lab3/agent.png)

3. Click the orange **Edit in Agent Builder** button
4. Under **Select Model** click the small **pen icon** 

![pen](/images/lab3/pen.png)

5. Under **Categories** select **Amazon**
6. Under **Models** select **Amazon Nova Pro**
7. Under **Inference** select **Inference profiles**, then select **US Nova Pro**
8. Click **Apply**

![profile](/images/lab3/profile.png)

9. Click the **Additional settings** drop down
10. Under **User input** select **Enabled** option

![user](/images/lab3/user.png)

11. Scroll to the top of the screen and click the orange **Save and exit** button.
12. Under **Prepare the Agent to test the latest changes.** click on the **Prepare** button
13. Scroll down to the **Alias** section in the Amazon Bedrock Agent Screen.
14. Select the current Alias and click the **Edit** button.

![alias](/images/lab3/alias.png)

15. Under **Associate a version** select the **Create a new version and associate it to this alias** option.
16. Click **Save**

![save](/images/lab3/save.png)

### Step 4: Upload Lambda Function Code
After the CloudFormation stack deploys successfully, you'll need to upload the code for each Lambda function:

**For each Lambda function below:**
1. Go to **AWS Lambda Console**
2. Select the Lambda function
3. Scroll down to the **Code** section
4. Click **Upload from** → **.zip file**
5. Choose the corresponding zip file from the `/assets` folder

**Lambda Functions and their zip files:**
- **CIBAAuthenticationFunction** ← `ciba.zip`
- **FlaskWebApplication** ← `flask_app.zip` 
- **FGAAuthorizationFunction** ← `fga_check.zip`
- **FGATokensetFunction** ← `token_vault.zip`

### Step 5: Configure FGAAuthorizationFunction Lambda
1. In the Lambda console click on the **FGAAuthorizationFunction** Lambda
2. Select the **Configuration** tab
3. On the lefe pane select **Environment Variables**
4. Click the **Edit** button
5. Update the following environment variables with your Auth0 FGA configuration values:
   - **FGA_AUTHORIZATION_MODEL_ID**: Replace `YOUR_FGA_AUTHORIZATION_MODEL_ID` with your actual FGA authorization model ID
   - **FGA_CLIENT_ID**: Replace `YOUR_FGA_CLIENT_ID` with your FGA client ID from Auth0
   - **FGA_CLIENT_SECRET**: Replace `YOUR_FGA_CLIENT_SECRET` with your FGA client secret from Auth0
   - **FGA_STORE_ID**: Replace `YOUR_FGA_STORE_ID` with your FGA store ID from Auth0
7. Click the **Save** button to apply your changes

![FGA](/images/lab4/FGA.png)

### Step 6: Configure FGATokensetFunction Lambda
1. In the Lambda console click on the **FGATokensetFunction** Lambda
2. Select the **Configuration** tab
3. On the lefe pane select **Environment Variables**
4. Click the **Edit** button
5. Update the following environment variables with your Auth0 FGA configuration values:
   - **OKTA_DOMAIN**: Replace `https://youroktadomain.com` with your Okta domain
6. Click the **Save** button to apply your changes 

### Step 7: Configure CIBA Lambda Variables
1. In the Lambda console select the **CIBAAuthenticationFunction** Lambda
2. Select the **Configuration** tab
3. On the lefe pane select **Environment Variables**
4. Click the **Edit** button
5. Update the following environment variables with your Auth0 CIBA configuration:
   - **AUTH0_CLIENT_ID**: Replace `YOUR_CLIENT_ID` with your Auth0 application client ID
   - **AUTH0_CLIENT_SECRET**: Replace `YOUR_CLIENT_SECRET` with your Auth0 application client secret
   - **AUTH0_DOMAIN**: Replace `YOUR_AUTH0_DOMAIN` with your Auth0 domain
6. Click the **Save** button to apply your changes

![ciba](/images/lab4/ciba.png)

### Step 8: Configure  FlaskWebApplication Variables
1. In the Lambda console select the **FlaskWebApplication** Lambda
2. Select the **Configuration** tab
3. On the lefe pane select **Environment Variables**
4. Click the **Edit** button
5. Update the following environment variables with your Auth0 configuration:
   - **AUTH0_CLIENT_ID**: Replace with your Auth0 application client ID
   - **AUTH0_CLIENT_SECRET**: Replace with your Auth0 application client secret
   - **AUTH0_DOMAIN**: Replace with your Auth0 domain
6. Click the **Save** button to apply your changes
7. Copy and paste the **AUTH0_CALLBACK_URL** value as you will need this later.
Example: of what to copy **https://xxxxxxx.execute-api.us-east-1.amazonaws.com/prod/callback**

![flask](/images/lab4/flask.png)

### Step 9: Configure Auth0 App with API Gateway Callback URLs
1. Go back to your **Auth0 Console**
2. On the left pane click on **Applications**, and select the **Bedrock Flask App**

![flaskapp](/images/lab4/flaskapp.png)

3. Click on the **Settings** Tab
4. Scroll down to **Application URIs** section
5. Using the link you copied in **Step 4** Paste the link in the following section

   - **Allowed Callback URLs**: https://xxxxxx.execute-api.us-east-1.amazonaws.com/prod/callback
   - **Application Login URI**: https://xxxxxxx.execute-api.us-east-1.amazonaws.com/prod/login
   - **Allowed Logout URLs**: https://xxxxxxx.execute-api.us-east-1.amazonaws.com/prod/logout

![url](/images/lab4/url.png)

6. Make sure all 3 URLS match the picture above, except with your actual gateway link at the begining of the URLs.
7. Click **Save**

### Step 10: Access the Web Application
1. Open a new **Private Browser Window**
2. Navigate to your login **API Gateway URL** from Lab 4 (Example: https://xxxxxxx.execute-api.us-east-1.amazonaws.com/prod/)
3. At the login screen, select the bottom option that says **Continue with 'Name of Connection'**

![log](/images/lab5/log.png)

4. You will be redirected to an Okta login screen, enter the following credentials
- Username: Okta User
- Password: Okta User password

![okta](/images/lab5/okta.png)

5. On your mobile device, please download the **Auth0 Guardian** app
6. Once downloaded, click **Continue**

![select](/images/lab5/select.png)

7. Open the **Auth0 Guardian** App and on the top right click the **+Add** button
8. Select **Scan QR Code**
9. Using your mobile phone's camera through the Auth0 Guardian app, scan the QR code displayed on your computer screen to link your device with Auth0.
10. You will be redirected to the **Amazon Bedrock powered by Auth0** chatbot.

**Do not interact with the chatbot yet** - we need to disable MFA first, which we will do in Step 2.

### Step 11: Disable MFA Policy
1. Open your **Auth0 Dashboard** window or tab.
2. On the left pane, under **Security** section, click on **Multi-factor Auth**
3. Scroll to **Require Multi-factor Auth**, change the MFA requirement to **Never**
4. Click **Save**
5. On the **Disabling MFA for all applications** screen click the red **Disable** button.

![disable](/images/lab5/disable.png)

We're temporarily disabling MFA to focus on testing the FGA authorization and CIBA flows without MFA interference

### Step 12: Interacting with the Bedrock AI Agent
1. Return to your web application window
2. You should see a clean chatbot interface with, like the image below

![chatbot](/images/lab5/chatbot.png)

We first want to test the Bedrock Action Group that retrieves Okta group information. This action group connects to an Okta environment to fetch user group memberships. The current user has admin rights and permissions configured through the FGA (Fine-Grained Authorization) console we set up in Lab 2. This demonstrates both the Amazon Bedrock Action Group integration and the FGA authorization system working together.

3. Ask the chatbot: **What are the Okta groups for user 'youroktauser@mail.com'** (replace with your provided workshop user email)

![group](/images/lab5/group.png)

The Bedrock agent successfully retrieved the user's Okta group memberships by calling the FGA Authorization Lambda function, which validated your permissions, then invoked the User Management Lambda function to query the Okta API. This demonstrates the complete integration between Amazon Bedrock, Auth0 FGA, and Okta working together

4. Now ask the chatbot: **Reset password for user 'youroktauser@mail.com'** (replace with your provided workshop user email)
5. You will receive a notifcation on your mobile device from the **Auth0 Guardian** App.
6. Open the notification and select **Approve** to approve the CIBA authentication request for the password reset operation.

![ciba](/images/lab5/ciba.png)

When you requested the password reset, the Bedrock agent triggered the CIBA Authentication Lambda function, which initiated a backchannel authentication request through Auth0. This sent a push notification to your registered Guardian device for verification. By approving the request, you completed the CIBA flow, allowing the sensitive password reset operation to proceed. This demonstrates how CIBA adds an extra security layer for high-risk actions, ensuring that even authenticated users must provide additional verification for sensitive operations

### Step 13: Removing FGA Tuple Permissions
1. Open your **FGA Dashboard** window or tab.
2. On the left pane click on **Tuple Management**
3. Locate the tuple that grants your user permission to read Okta groups (it should show your email, "read_okta" relation, and "okta groups" object) and click the small red trash icon to delete this tuple.
4. When promted click **Confirm** to delete tuple.

![tuple](/images/lab5/tuple.png)

By removing this tuple, we've revoked the FGA permission that allowed your user to access Okta group information. This will demonstrate how fine-grained authorization works in real-time

5. Return to your web application window
6. Ask the chatbot the same question as before: **What are the Okta groups for user 'youroktauser@mail.com'** (replace with your provided workshop user email)
7. This time, you should receive an authorization denied message

![ask](/images/lab5/ask.png)

The Bedrock agent attempted to call the FGA Authorization Lambda function to check your permissions, but since we deleted the tuple, the FGA system returned "not authorized." The agent respected this security decision and blocked the request, demonstrating how fine-grained authorization prevents unauthorized access in real-time
