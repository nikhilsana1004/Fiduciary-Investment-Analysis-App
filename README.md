# 💼 Fiduciary Investment Analysis App

An AI-powered investment analysis app with role-based access, built using AWS Bedrock (Claude 3 Haiku), AWS Cognito, and AWS Comprehend for PII detection and sentiment analysis.

## 🌟 Features
- 🔐 Secure Login via AWS Cognito with role-based access
- 🤖 AI Insights using Bedrock (Claude 3 Haiku)
- 🛡️ Guardrails per user role (Employee, Accounts, Portfolio, Admin)
- 🔍 PII Detection with AWS Comprehend
- 📊 Sentiment Analysis for responses
- 📁 S3 Integration for secure data storage

## 🏗️ Architecture
Frontend: Streamlit  
Auth: AWS Cognito  
AI Model: AWS Bedrock (Claude 3 Haiku)  
NLP: AWS Comprehend  
Storage: Amazon S3  
Security: AWS Guardrails  

## 📋 Prerequisites
- Python ≥ 3.8  
- AWS account with Bedrock, Cognito, Comprehend, and S3  
- AWS CLI configured  
- Cognito User Pool with user groups: `Employee`, `Accounts_Team`, `Portfolio`, `Admin`  
- Bedrock Guardrails configured per role  

## ⚙️ Quick Start
```bash
# 1. Clone the repo
git clone https://github.com/nikhilsana1004/fiduciary-investment-analysis.git
cd fiduciary-investment-analysis

# 2. Setup environment
python -m venv venv && source venv/bin/activate  # macOS/Linux
# or venv\Scripts\activate  # Windows

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure AWS
aws configure

# 5. Setup environment variables
cp .env.example .env
Edit .env:

env
Copy code
AWS_REGION=us-west-2
USER_POOL_ID=your_user_pool_id
CLIENT_ID=your_client_id
MODEL_ID=anthropic.claude-3-haiku-20240307-v1:0
S3_BUCKET_NAME=your-s3-bucket
GUARDRAIL_ID_EMPLOYEE=xxxx
GUARDRAIL_ID_ACCOUNTS_TEAM=xxxx
GUARDRAIL_ID_PORTFOLIO=xxxx
GUARDRAIL_ID_ADMIN=xxxx
MAX_TOKENS=1000
GUARDRAIL_VERSION=DRAFT
▶️ Run the App
bash
Copy code
streamlit run app.py
Visit http://localhost:8501

💡 Usage
Login with Cognito credentials (role-based dashboard)

Enter investment-related query → “Generate Custom Analysis”

AI generates insights based on your role and guardrails

View PII and Sentiment detection results instantly

👥 Roles
Role	Access Scope
Employee	Basic insights
Accounts Team	Account-specific analytics
Portfolio	Investment recommendations
Admin	Full access & management

🔒 Security Best Practices
Never commit .env or AWS credentials

Use IAM roles instead of access keys

Enable MFA in Cognito

Encrypt & restrict access to S3

Regularly review guardrails & logs

🐛 Troubleshooting
Issue	Fix
Auth failed	Verify USER_POOL_ID, CLIENT_ID & Cognito permissions
No user group found	Ensure user is in a Cognito group
S3 access error	Check S3_BUCKET_NAME and IAM GetObject
Bedrock/Comprehend failure	Confirm model access & region setup

🤝 Contributing
bash
Copy code
git checkout -b feature/AmazingFeature
git commit -m "Add AmazingFeature"
git push origin feature/AmazingFeature
Follow PEP 8, include error handling, and test across roles.


📧 Contact
Author: Nikhil Sana
GitHub: @nikhilsana1004
Project: fiduciary-investment-analysis

🗺️ Roadmap
MFA support

Conversation history

Sentiment trend visualizations

Admin dashboard

Audit logging & report export

Multi-language support

Docker deployment

⚖️ Compliance
PII Detection & masking

Role-Based Access for data privacy

AI Guardrails for compliant responses

Audit Logs for SEC/FINRA review
Compliant with GDPR, CCPA, and financial data regulations.

⭐ If you found this project helpful, please give it a star!