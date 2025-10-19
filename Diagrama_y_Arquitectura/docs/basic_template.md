# Threat Model Report

## System Overview
This threat model describes the architecture and data flows for the AWS-based Ecommerce Web Application.

## Components
- AWS WAF
- Application Load Balancer
- API Gateway
- Lambda Functions
- DynamoDB
- S3 Bucket

## Security Controls
| Control | Description | Status |
|----------|--------------|--------|
| Encryption at Rest | All data encrypted with AES-256 | ✅ |
| TLS in Transit | Enforced TLS 1.2+ | ✅ |
| IAM Roles | Scoped permissions per function | ✅ |
| WAF Rules | SQLi/XSS protection | ✅ |

## Identified Threats
<div class="callout warn">
<b>Risk:</b> Public S3 bucket without restricted access policy.
</div>

## Recommendations
- Enable AWS S3 Block Public Access.
- Enforce strict IAM least privilege.
- Rotate API Gateway tokens periodically.
