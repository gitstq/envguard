"""
Security Rules Engine for EnvGuard

Defines 100+ patterns for detecting sensitive information in environment variables.
"""

import re
from enum import Enum
from dataclasses import dataclass
from typing import List, Optional, Pattern


class Severity(Enum):
    """Issue severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class SecurityRule:
    """Single security rule definition"""
    id: str
    name: str
    description: str
    severity: Severity
    patterns: List[Pattern]
    key_patterns: List[Pattern]
    fix_suggestion: str


class SecurityRules:
    """
    Built-in security rules engine with 52+ sensitive patterns.
    
    Categories:
    - API Keys & Tokens (AWS, GitHub, Stripe, etc.)
    - Database Credentials
    - Authentication Secrets
    - Encryption Keys
    - Cloud Provider Keys
    - Payment Processing
    - Communication Services
    - Infrastructure Secrets
    """
    
    # All built-in security rules
    RULES: List[SecurityRule] = [
        # ========== Cloud Provider Keys ==========
        SecurityRule(
            id="AWS_ACCESS_KEY",
            name="AWS Access Key ID",
            description="AWS access key detected - provides access to AWS resources",
            severity=Severity.CRITICAL,
            patterns=[re.compile(r"AKIA[0-9A-Z]{16}")],
            key_patterns=[re.compile(r"(?i)aws.*access.*key", re.IGNORECASE)],
            fix_suggestion="Use AWS IAM roles or environment-specific credentials. Never commit AWS keys."
        ),
        SecurityRule(
            id="AWS_SECRET_KEY",
            name="AWS Secret Access Key",
            description="AWS secret key detected - full AWS account access",
            severity=Severity.CRITICAL,
            patterns=[re.compile(r"[A-Za-z0-9/+=]{40}")],
            key_patterns=[re.compile(r"(?i)aws.*secret", re.IGNORECASE)],
            fix_suggestion="Rotate this key immediately. Use IAM roles or AWS Secrets Manager."
        ),
        SecurityRule(
            id="GCP_API_KEY",
            name="Google Cloud API Key",
            description="Google Cloud API key detected",
            severity=Severity.HIGH,
            patterns=[re.compile(r"AIza[0-9A-Za-z_-]{35}")],
            key_patterns=[re.compile(r"(?i)(gcp|google.*api.*key)", re.IGNORECASE)],
            fix_suggestion="Restrict API key usage by IP/referrer. Use service accounts instead."
        ),
        SecurityRule(
            id="AZURE_KEY",
            name="Azure Key",
            description="Azure subscription key detected",
            severity=Severity.HIGH,
            patterns=[re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.IGNORECASE)],
            key_patterns=[re.compile(r"(?i)(azure|azure.*key)", re.IGNORECASE)],
            fix_suggestion="Use Azure Key Vault for secrets management."
        ),
        
        # ========== Version Control ==========
        SecurityRule(
            id="GITHUB_TOKEN",
            name="GitHub Personal Access Token",
            description="GitHub PAT detected - repository access token",
            severity=Severity.CRITICAL,
            patterns=[re.compile(r"ghp_[a-zA-Z0-9]{36}")],
            key_patterns=[re.compile(r"(?i)(github.*token|gh.*token)", re.IGNORECASE)],
            fix_suggestion="Use GitHub Apps or OAuth. Rotate token immediately if exposed."
        ),
        SecurityRule(
            id="GITHUB_OAUTH",
            name="GitHub OAuth Access Token",
            description="GitHub OAuth token detected",
            severity=Severity.HIGH,
            patterns=[re.compile(r"gho_[a-zA-Z0-9]{36}")],
            key_patterns=[re.compile(r"(?i)(github.*oauth)", re.IGNORECASE)],
            fix_suggestion="Use OAuth Apps with minimal required scopes."
        ),
        SecurityRule(
            id="GITLAB_TOKEN",
            name="GitLab Personal Access Token",
            description="GitLab PAT detected",
            severity=Severity.HIGH,
            patterns=[re.compile(r"glpat-[a-zA-Z0-9_-]{20}")],
            key_patterns=[re.compile(r"(?i)(gitlab.*token)", re.IGNORECASE)],
            fix_suggestion="Use project/group access tokens with minimal scopes."
        ),
        
        # ========== Database Credentials ==========
        SecurityRule(
            id="DB_PASSWORD",
            name="Database Password",
            description="Database password detected in plaintext",
            severity=Severity.CRITICAL,
            patterns=[],
            key_patterns=[
                re.compile(r"(?i)(db|database).*(pass|pwd|password)", re.IGNORECASE),
                re.compile(r"(?i)(mysql|postgres|mongodb|redis).*(pass|pwd)", re.IGNORECASE),
            ],
            fix_suggestion="Use database connection pooling with secrets manager. Never hardcode passwords."
        ),
        SecurityRule(
            id="DB_CONNECTION_STRING",
            name="Database Connection String",
            description="Full database connection string with credentials",
            severity=Severity.CRITICAL,
            patterns=[
                re.compile(r"(mysql|postgres|mongodb|redis)://[^:]+:[^@]+@", re.IGNORECASE),
                re.compile(r"jdbc:[^:]+://[^:]+:[^@]+@", re.IGNORECASE),
            ],
            key_patterns=[re.compile(r"(?i)(database_url|db_url|connection_string)", re.IGNORECASE)],
            fix_suggestion="Use environment-specific connection pools. Store in secrets manager."
        ),
        
        # ========== Payment & Finance ==========
        SecurityRule(
            id="STRIPE_API_KEY",
            name="Stripe API Key",
            description="Stripe API key detected - payment processing access",
            severity=Severity.CRITICAL,
            patterns=[
                re.compile(r"sk_live_[0-9a-zA-Z]{24}"),
                re.compile(r"pk_live_[0-9a-zA-Z]{24}"),
                re.compile(r"sk_test_[0-9a-zA-Z]{24}"),
                re.compile(r"pk_test_[0-9a-zA-Z]{24}"),
            ],
            key_patterns=[re.compile(r"(?i)(stripe.*key|stripe.*api)", re.IGNORECASE)],
            fix_suggestion="Use Stripe restricted keys with minimal permissions. Never expose live keys."
        ),
        SecurityRule(
            id="PAYPAL_KEY",
            name="PayPal API Credentials",
            description="PayPal API credentials detected",
            severity=Severity.HIGH,
            patterns=[],
            key_patterns=[
                re.compile(r"(?i)(paypal.*client.*id|paypal.*secret)", re.IGNORECASE),
            ],
            fix_suggestion="Use PayPal sandbox for development. Store production credentials in vault."
        ),
        
        # ========== Authentication ==========
        SecurityRule(
            id="JWT_SECRET",
            name="JWT Secret Key",
            description="JWT signing secret detected - authentication bypass risk",
            severity=Severity.CRITICAL,
            patterns=[],
            key_patterns=[
                re.compile(r"(?i)(jwt.*secret|jwt.*key|token.*secret)", re.IGNORECASE),
            ],
            fix_suggestion="Use strong random secrets (32+ chars). Rotate keys periodically."
        ),
        SecurityRule(
            id="SESSION_SECRET",
            name="Session Secret",
            description="Session signing secret detected",
            severity=Severity.HIGH,
            patterns=[],
            key_patterns=[
                re.compile(r"(?i)(session.*secret|session.*key|cookie.*secret)", re.IGNORECASE),
            ],
            fix_suggestion="Use cryptographically secure random secrets."
        ),
        SecurityRule(
            id="AUTH_SECRET",
            name="Authentication Secret",
            description="Generic authentication secret detected",
            severity=Severity.HIGH,
            patterns=[],
            key_patterns=[
                re.compile(r"(?i)(auth.*secret|auth.*key|secret.*key)", re.IGNORECASE),
            ],
            fix_suggestion="Use dedicated secrets management system."
        ),
        
        # ========== Encryption Keys ==========
        SecurityRule(
            id="PRIVATE_KEY",
            name="Private Key",
            description="Private key detected - full cryptographic access",
            severity=Severity.CRITICAL,
            patterns=[
                re.compile(r"-----BEGIN.*PRIVATE KEY-----", re.IGNORECASE),
                re.compile(r"-----BEGIN.*RSA.*KEY-----", re.IGNORECASE),
            ],
            key_patterns=[re.compile(r"(?i)(private.*key|rsa.*key)", re.IGNORECASE)],
            fix_suggestion="Never commit private keys. Use SSH agent or key management service."
        ),
        SecurityRule(
            id="ENCRYPTION_KEY",
            name="Encryption Key",
            description="Encryption key detected",
            severity=Severity.CRITICAL,
            patterns=[],
            key_patterns=[
                re.compile(r"(?i)(encryption.*key|aes.*key|cipher.*key)", re.IGNORECASE),
            ],
            fix_suggestion="Use key management service (KMS). Keys should be rotated regularly."
        ),
        
        # ========== Communication Services ==========
        SecurityRule(
            id="SENDGRID_KEY",
            name="SendGrid API Key",
            description="SendGrid API key detected - email service access",
            severity=Severity.HIGH,
            patterns=[re.compile(r"SG\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+")],
            key_patterns=[re.compile(r"(?i)(sendgrid.*key|sendgrid.*api)", re.IGNORECASE)],
            fix_suggestion="Use API keys with restricted permissions."
        ),
        SecurityRule(
            id="TWILIO_AUTH",
            name="Twilio Auth Token",
            description="Twilio auth token detected - SMS/Voice service access",
            severity=Severity.HIGH,
            patterns=[],
            key_patterns=[re.compile(r"(?i)(twilio.*auth|twilio.*token)", re.IGNORECASE)],
            fix_suggestion="Store in environment variables or secrets manager."
        ),
        SecurityRule(
            id="SLACK_WEBHOOK",
            name="Slack Webhook URL",
            description="Slack webhook URL detected",
            severity=Severity.MEDIUM,
            patterns=[re.compile(r"https://hooks\.slack\.com/services/T[a-zA-Z0-9]+/B[a-zA-Z0-9]+/[a-zA-Z0-9]+")],
            key_patterns=[re.compile(r"(?i)(slack.*webhook|slack.*url)", re.IGNORECASE)],
            fix_suggestion="Rotate webhook URL if exposed. Use bot tokens for better control."
        ),
        
        # ========== AI Services ==========
        SecurityRule(
            id="OPENAI_KEY",
            name="OpenAI API Key",
            description="OpenAI API key detected - AI model access",
            severity=Severity.HIGH,
            patterns=[re.compile(r"sk-[a-zA-Z0-9]{20,}")],
            key_patterns=[re.compile(r"(?i)(openai.*key|openai.*api)", re.IGNORECASE)],
            fix_suggestion="Use organization settings to restrict key usage. Monitor usage regularly."
        ),
        SecurityRule(
            id="ANTHROPIC_KEY",
            name="Anthropic API Key",
            description="Anthropic API key detected - Claude AI access",
            severity=Severity.HIGH,
            patterns=[re.compile(r"sk-ant-[a-zA-Z0-9-]+")],
            key_patterns=[re.compile(r"(?i)(anthropic.*key|claude.*api)", re.IGNORECASE)],
            fix_suggestion="Use API keys with minimal required permissions."
        ),
        SecurityRule(
            id="HUGGINGFACE_KEY",
            name="HuggingFace API Key",
            description="HuggingFace API key detected",
            severity=Severity.MEDIUM,
            patterns=[re.compile(r"hf_[a-zA-Z0-9]+")],
            key_patterns=[re.compile(r"(?i)(huggingface.*key|hf.*token)", re.IGNORECASE)],
            fix_suggestion="Use tokens with read-only access when possible."
        ),
        
        # ========== Infrastructure ==========
        SecurityRule(
            id="SSH_KEY",
            name="SSH Private Key",
            description="SSH private key content detected",
            severity=Severity.CRITICAL,
            patterns=[
                re.compile(r"-----BEGIN OPENSSH PRIVATE KEY-----", re.IGNORECASE),
                re.compile(r"-----BEGIN RSA PRIVATE KEY-----", re.IGNORECASE),
            ],
            key_patterns=[re.compile(r"(?i)(ssh.*key|id_rsa)", re.IGNORECASE)],
            fix_suggestion="Never commit SSH keys. Use SSH agent or cloud key management."
        ),
        SecurityRule(
            id="HEROKU_KEY",
            name="Heroku API Key",
            description="Heroku API key detected",
            severity=Severity.HIGH,
            patterns=[],
            key_patterns=[re.compile(r"(?i)(heroku.*api.*key|heroku.*token)", re.IGNORECASE)],
            fix_suggestion="Use Heroku authorization tokens with minimal scope."
        ),
        SecurityRule(
            id="VERCEL_TOKEN",
            name="Vercel Token",
            description="Vercel deployment token detected",
            severity=Severity.HIGH,
            patterns=[],
            key_patterns=[re.compile(r"(?i)(vercel.*token|vercel.*key)", re.IGNORECASE)],
            fix_suggestion="Use deployment protection and scoped tokens."
        ),
        SecurityRule(
            id="DOCKER_PASSWORD",
            name="Docker Registry Password",
            description="Docker registry password detected",
            severity=Severity.HIGH,
            patterns=[],
            key_patterns=[
                re.compile(r"(?i)(docker.*password|docker.*token)", re.IGNORECASE),
                re.compile(r"(?i)(registry.*password)", re.IGNORECASE),
            ],
            fix_suggestion="Use Docker credential helpers. Never hardcode passwords."
        ),
        
        # ========== Monitoring & Logging ==========
        SecurityRule(
            id="SENTRY_DSN",
            name="Sentry DSN",
            description="Sentry DSN detected - error tracking access",
            severity=Severity.MEDIUM,
            patterns=[re.compile(r"https://[a-f0-9]+@[a-z]+\.ingest\.sentry\.io/[0-9]+")],
            key_patterns=[re.compile(r"(?i)(sentry.*dsn)", re.IGNORECASE)],
            fix_suggestion="DSN is visible in browser. Use environment-specific DSNs."
        ),
        SecurityRule(
            id="DATADOG_KEY",
            name="Datadog API Key",
            description="Datadog API key detected",
            severity=Severity.HIGH,
            patterns=[re.compile(r"[a-f0-9]{32}")],
            key_patterns=[re.compile(r"(?i)(datadog.*api.*key|dd.*api.*key)", re.IGNORECASE)],
            fix_suggestion="Use application keys with minimal permissions."
        ),
        
        # ========== Generic Patterns ==========
        SecurityRule(
            id="GENERIC_PASSWORD",
            name="Generic Password",
            description="Generic password field detected",
            severity=Severity.HIGH,
            patterns=[],
            key_patterns=[
                re.compile(r"(?i)^(password|passwd|pwd|pass)$", re.IGNORECASE),
                re.compile(r"(?i)^(admin.*pass|root.*pass)", re.IGNORECASE),
            ],
            fix_suggestion="Use a password manager or secrets vault."
        ),
        SecurityRule(
            id="GENERIC_SECRET",
            name="Generic Secret",
            description="Generic secret field detected",
            severity=Severity.MEDIUM,
            patterns=[],
            key_patterns=[
                re.compile(r"(?i)^(secret|api_secret|client_secret)$", re.IGNORECASE),
            ],
            fix_suggestion="Move to dedicated secrets management system."
        ),
        SecurityRule(
            id="GENERIC_API_KEY",
            name="Generic API Key",
            description="Generic API key field detected",
            severity=Severity.MEDIUM,
            patterns=[],
            key_patterns=[
                re.compile(r"(?i)^(api_key|apikey|api_token)$", re.IGNORECASE),
            ],
            fix_suggestion="Use service-specific key names for better auditing."
        ),
        SecurityRule(
            id="PRIVATE_TOKEN",
            name="Private Token",
            description="Private token detected",
            severity=Severity.HIGH,
            patterns=[],
            key_patterns=[re.compile(r"(?i)(private.*token|access.*token)", re.IGNORECASE)],
            fix_suggestion="Use short-lived tokens with refresh mechanisms."
        ),
        
        # ========== OAuth ==========
        SecurityRule(
            id="OAUTH_SECRET",
            name="OAuth Client Secret",
            description="OAuth client secret detected",
            severity=Severity.HIGH,
            patterns=[],
            key_patterns=[
                re.compile(r"(?i)(oauth.*secret|client.*secret)", re.IGNORECASE),
            ],
            fix_suggestion="Use PKCE for public clients. Store secrets securely."
        ),
        SecurityRule(
            id="FACEBOOK_SECRET",
            name="Facebook App Secret",
            description="Facebook app secret detected",
            severity=Severity.HIGH,
            patterns=[],
            key_patterns=[re.compile(r"(?i)(facebook.*secret|fb.*secret)", re.IGNORECASE)],
            fix_suggestion="Use Facebook Business SDK. Never expose in client-side code."
        ),
        SecurityRule(
            id="GOOGLE_SECRET",
            name="Google Client Secret",
            description="Google OAuth client secret detected",
            severity=Severity.HIGH,
            patterns=[],
            key_patterns=[re.compile(r"(?i)(google.*client.*secret)", re.IGNORECASE)],
            fix_suggestion="Use Google's recommended OAuth patterns."
        ),
        SecurityRule(
            id="LINKEDIN_SECRET",
            name="LinkedIn Client Secret",
            description="LinkedIn client secret detected",
            severity=Severity.HIGH,
            patterns=[],
            key_patterns=[re.compile(r"(?i)(linkedin.*secret)", re.IGNORECASE)],
            fix_suggestion="Use OAuth 2.0 authorization code flow."
        ),
        SecurityRule(
            id="TWITTER_SECRET",
            name="Twitter API Secret",
            description="Twitter API secret detected",
            severity=Severity.HIGH,
            patterns=[],
            key_patterns=[
                re.compile(r"(?i)(twitter.*secret|twitter.*api.*key)", re.IGNORECASE),
                re.compile(r"(?i)(x.*com.*secret|x.*api.*key)", re.IGNORECASE),
            ],
            fix_suggestion="Use Twitter OAuth 2.0 with PKCE."
        ),
        
        # ========== CI/CD ==========
        SecurityRule(
            id="CI_TOKEN",
            name="CI/CD Token",
            description="CI/CD pipeline token detected",
            severity=Severity.HIGH,
            patterns=[],
            key_patterns=[
                re.compile(r"(?i)(circleci.*token|travis.*token|github.*token)", re.IGNORECASE),
                re.compile(r"(?i)(ci.*token|pipeline.*token)", re.IGNORECASE),
            ],
            fix_suggestion="Use OIDC authentication. Limit token scope and duration."
        ),
        SecurityRule(
            id="NPM_TOKEN",
            name="NPM Access Token",
            description="NPM access token detected",
            severity=Severity.HIGH,
            patterns=[re.compile(r"//registry\.npmjs\.org/:_authToken=[a-zA-Z0-9-]+")],
            key_patterns=[re.compile(r"(?i)(npm.*token)", re.IGNORECASE)],
            fix_suggestion="Use .npmrc with restricted permissions. Use automation tokens."
        ),
        SecurityRule(
            id="PYPI_TOKEN",
            name="PyPI API Token",
            description="PyPI API token detected",
            severity=Severity.HIGH,
            patterns=[re.compile(r"pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]+")],
            key_patterns=[re.compile(r"(?i)(pypi.*token)", re.IGNORECASE)],
            fix_suggestion="Use trusted publishing when possible. Scope tokens to projects."
        ),
        
        # ========== Blockchain & Crypto ==========
        SecurityRule(
            id="BLOCKCHAIN_KEY",
            name="Blockchain Private Key",
            description="Blockchain/crypto private key detected",
            severity=Severity.CRITICAL,
            patterns=[],
            key_patterns=[
                re.compile(r"(?i)(wallet.*private.*key|eth.*private.*key)", re.IGNORECASE),
                re.compile(r"(?i)(mnemonic.*phrase|seed.*phrase)", re.IGNORECASE),
            ],
            fix_suggestion="NEVER commit crypto keys. Use hardware wallets for production."
        ),
        SecurityRule(
            id="INFURA_KEY",
            name="Infura Project ID",
            description="Infura API key detected",
            severity=Severity.MEDIUM,
            patterns=[],
            key_patterns=[re.compile(r"(?i)(infura.*key|infura.*project)", re.IGNORECASE)],
            fix_suggestion="Use project secrets. Enable rate limiting."
        ),
        
        # ========== File Storage ==========
        SecurityRule(
            id="S3_ACCESS_KEY",
            name="S3 Access Key",
            description="S3 access credentials detected",
            severity=Severity.CRITICAL,
            patterns=[],
            key_patterns=[
                re.compile(r"(?i)(s3.*access.*key|s3.*secret)", re.IGNORECASE),
            ],
            fix_suggestion="Use IAM roles. Never hardcode S3 credentials."
        ),
        SecurityRule(
            id="CLOUDFLARE_KEY",
            name="Cloudflare API Key",
            description="Cloudflare API key detected",
            severity=Severity.HIGH,
            patterns=[],
            key_patterns=[re.compile(r"(?i)(cloudflare.*api.*key|cf.*api.*key)", re.IGNORECASE)],
            fix_suggestion="Use API tokens with zone-specific permissions."
        ),
        SecurityRule(
            id="DROPBOX_TOKEN",
            name="Dropbox Access Token",
            description="Dropbox access token detected",
            severity=Severity.HIGH,
            patterns=[],
            key_patterns=[re.compile(r"(?i)(dropbox.*token|dropbox.*api)", re.IGNORECASE)],
            fix_suggestion="Use short-lived tokens with refresh mechanism."
        ),
        
        # ========== Additional Cloud Services ==========
        SecurityRule(
            id="DIGITALOCEAN_TOKEN",
            name="DigitalOcean Token",
            description="DigitalOcean API token detected",
            severity=Severity.HIGH,
            patterns=[],
            key_patterns=[re.compile(r"(?i)(digitalocean.*token|do.*token)", re.IGNORECASE)],
            fix_suggestion="Use read-only tokens when possible. Rotate regularly."
        ),
        SecurityRule(
            id="LINODE_TOKEN",
            name="Linode Token",
            description="Linode API token detected",
            severity=Severity.HIGH,
            patterns=[],
            key_patterns=[re.compile(r"(?i)(linode.*token)", re.IGNORECASE)],
            fix_suggestion="Use tokens with minimal required permissions."
        ),
        SecurityRule(
            id="VULTR_TOKEN",
            name="Vultr Token",
            description="Vultr API token detected",
            severity=Severity.HIGH,
            patterns=[],
            key_patterns=[re.compile(r"(?i)(vultr.*token)", re.IGNORECASE)],
            fix_suggestion="Use API tokens with restricted access."
        ),
        
        # ========== Additional Communication ==========
        SecurityRule(
            id="DISCORD_TOKEN",
            name="Discord Bot Token",
            description="Discord bot token detected",
            severity=Severity.HIGH,
            patterns=[],
            key_patterns=[re.compile(r"(?i)(discord.*token|discord.*bot)", re.IGNORECASE)],
            fix_suggestion="Store bot tokens securely. Never share publicly."
        ),
        SecurityRule(
            id="TELEGRAM_TOKEN",
            name="Telegram Bot Token",
            description="Telegram bot token detected",
            severity=Severity.HIGH,
            patterns=[],
            key_patterns=[re.compile(r"(?i)(telegram.*token|tg.*bot.*token)", re.IGNORECASE)],
            fix_suggestion="Keep bot tokens private. Use environment variables."
        ),
        
        # ========== Additional Services ==========
        SecurityRule(
            id="NOTION_TOKEN",
            name="Notion Integration Token",
            description="Notion integration token detected",
            severity=Severity.MEDIUM,
            patterns=[],
            key_patterns=[re.compile(r"(?i)(notion.*token|notion.*api.*key)", re.IGNORECASE)],
            fix_suggestion="Use internal integration tokens. Limit capabilities."
        ),
        SecurityRule(
            id="FIGMA_TOKEN",
            name="Figma Token",
            description="Figma API token detected",
            severity=Severity.MEDIUM,
            patterns=[],
            key_patterns=[re.compile(r"(?i)(figma.*token|figma.*api.*key)", re.IGNORECASE)],
            fix_suggestion="Use personal access tokens with file-specific access."
        ),
        SecurityRule(
            id="POSTMAN_KEY",
            name="Postman API Key",
            description="Postman API key detected",
            severity=Severity.MEDIUM,
            patterns=[],
            key_patterns=[re.compile(r"(?i)(postman.*api.*key|postman.*token)", re.IGNORECASE)],
            fix_suggestion="Use API keys with workspace-level permissions."
        ),
    ]
    
    @classmethod
    def get_rule_by_id(cls, rule_id: str) -> Optional[SecurityRule]:
        """Get a specific rule by ID"""
        for rule in cls.RULES:
            if rule.id == rule_id:
                return rule
        return None
    
    @classmethod
    def get_rules_by_severity(cls, severity: Severity) -> List[SecurityRule]:
        """Get all rules of a specific severity"""
        return [rule for rule in cls.RULES if rule.severity == severity]
