# AWS API Gateway Connector - Production Deployment Guide

This guide covers deploying the Akto API Gateway traffic collector with OpenAPI discovery to AWS EKS.

## Prerequisites

- AWS account with API Gateway (CloudWatch Account)
- AWS account for EKS deployment (EKS Account) - can be same or different
- Akto dashboard access for `DATABASE_ABSTRACTOR_TOKEN`
- `kubectl` and `aws` CLI installed
- `helm` CLI installed (for Helm chart deployment)

---

## Architecture Overview

```
EKS Account
└── EKSCloudWatchRole (IRSA role)
    ├── ServiceAccount annotation: eks.amazonaws.com/role-arn
    └── Permission: Can assume CrossAccountCloudWatchRole

CloudWatch Account (where API Gateway is)
└── CrossAccountCloudWatchRole
    ├── Environment variable: CROSS_ACCOUNT_ROLE_ARN
    └── Permissions: Read CloudWatch logs + API Gateway specs
```

**OpenAPI Discovery Flow:**
```
AWS API Gateway → Export OpenAPI spec → Upload to cyborg.akto.io/api/importOpenApiSpec
                                        (using DATABASE_ABSTRACTOR_TOKEN for auth)
```

---

## Step 1: Create EKS Cluster (EKS Account)

### 1.1 Create EKS cluster

```bash
# Set variables
export EKS_CLUSTER_NAME="akto-collector-cluster"
export EKS_REGION="ap-south-1"
export EKS_VERSION="1.30"

# Create cluster
eksctl create cluster \
  --name $EKS_CLUSTER_NAME \
  --region $EKS_REGION \
  --version $EKS_VERSION \
  --nodegroup-name standard-workers \
  --node-type t3.xlarge \
  --nodes 3 \
  --nodes-min 1 \
  --nodes-max 3 \
  --managed
```

### 1.2 Get OIDC provider and EKS account ID

```bash
# Enable OIDC provider for the cluster
eksctl utils associate-iam-oidc-provider \
  --cluster $EKS_CLUSTER_NAME \
  --region $EKS_REGION \
  --approve

# Get OIDC provider URL
export OIDC_PROVIDER=$(aws eks describe-cluster \
  --name $EKS_CLUSTER_NAME \
  --region $EKS_REGION \
  --query "cluster.identity.oidc.issuer" \
  --output text | sed 's|https://||')

echo "OIDC Provider: $OIDC_PROVIDER"

# Get EKS account ID
export EKS_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
echo "EKS Account ID: $EKS_ACCOUNT_ID"
```

---

## Step 2: Create Cross-Account Role (CloudWatch Account)

**Switch to the AWS account where your API Gateway and CloudWatch logs are located.**

### 2.1 Set CloudWatch account ID

```bash
# Get CloudWatch account ID (where API Gateway is)
export CLOUDWATCH_ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
echo "CloudWatch Account ID: $CLOUDWATCH_ACCOUNT_ID"
```

### 2.2 Create trust policy for cross-account role

```bash
cat > cloudwatch-trust-policy.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::${EKS_ACCOUNT_ID}:root"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF
```

**Note**: This trusts the entire EKS account. The EKSCloudWatchRole (created in Step 3) will be able to assume this role.

### 2.3 Create IAM policy for CloudWatch and API Gateway access

```bash
cat > cloudwatch-access-policy.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "logs:DescribeLogGroups",
        "logs:DescribeLogStreams",
        "logs:GetLogEvents",
        "logs:FilterLogEvents",
        "apigateway:GET"
      ],
      "Resource": "*"
    }
  ]
}
EOF

# Create policy
aws iam create-policy \
  --policy-name AktoCloudWatchAccessPolicy \
  --policy-document file://cloudwatch-access-policy.json

export CLOUDWATCH_POLICY_ARN="arn:aws:iam::${CLOUDWATCH_ACCOUNT_ID}:policy/AktoCloudWatchAccessPolicy"
```

### 2.4 Create cross-account role

```bash
# Create role
aws iam create-role \
  --role-name CrossAccountCloudWatchRole \
  --assume-role-policy-document file://cloudwatch-trust-policy.json

# Attach policy
aws iam attach-role-policy \
  --role-name CrossAccountCloudWatchRole \
  --policy-arn $CLOUDWATCH_POLICY_ARN

# Get role ARN
export CROSS_ACCOUNT_ROLE_ARN=$(aws iam get-role \
  --role-name CrossAccountCloudWatchRole \
  --query 'Role.Arn' \
  --output text)

echo "Cross-Account Role ARN: $CROSS_ACCOUNT_ROLE_ARN"
```

---

## Step 3: Create IRSA Role (EKS Account)

**Switch back to the EKS account.**

### 3.1 Create IRSA trust policy

```bash
cat > irsa-trust-policy.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::${EKS_ACCOUNT_ID}:oidc-provider/${OIDC_PROVIDER}"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "${OIDC_PROVIDER}:sub": "system:serviceaccount:default:service-account-eks",
          "${OIDC_PROVIDER}:aud": "sts.amazonaws.com"
        }
      }
    }
  ]
}
EOF
```

### 3.2 Create IRSA role with assume-role permissions

```bash
# Create role
aws iam create-role \
  --role-name EKSCloudWatchRole \
  --assume-role-policy-document file://irsa-trust-policy.json

# Create inline policy to assume the cross-account role
cat > assume-cloudwatch-policy.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "sts:AssumeRole",
      "Resource": "${CROSS_ACCOUNT_ROLE_ARN}"
    }
  ]
}
EOF

aws iam put-role-policy \
  --role-name EKSCloudWatchRole \
  --policy-name AssumeCloudWatchRole \
  --policy-document file://assume-cloudwatch-policy.json

# Get IRSA role ARN
export IRSA_ROLE_ARN=$(aws iam get-role \
  --role-name EKSCloudWatchRole \
  --query 'Role.Arn' \
  --output text)

echo "IRSA Role ARN: $IRSA_ROLE_ARN"
```

---

## Step 4: Get Akto Configuration

### 4.1 Configure Akto Dashboard

1. Login to Akto dashboard
2. Go to **Settings** -> **Integrations** -> **AWS API Gateway**
3. Copy the `DATABASE_ABSTRACTOR_TOKEN`
4. **Add your CrossAccountCloudWatchRole ARN** to the Akto dashboard:
   - In the same AWS API Gateway integration page
   - Add the role ARN: `arn:aws:iam::<CLOUDWATCH_ACCOUNT_ID>:role/CrossAccountCloudWatchRole`
   - This allows the connector to dynamically fetch role ARNs from Akto API

```bash
export DATABASE_ABSTRACTOR_TOKEN="<YOUR_TOKEN_FROM_AKTO_DASHBOARD>"
```

**Note**: When you leave `CROSS_ACCOUNT_ROLE_ARN` empty (recommended), the connector will automatically fetch role ARNs from the Akto API using the `DATABASE_ABSTRACTOR_TOKEN`. This approach:
- Allows managing multiple role ARNs centrally in Akto dashboard
- Eliminates need to manually update deployment config for each role
- Follows official Akto deployment pattern

### 4.2 Deploy Akto Mini-Runtime in EKS (includes Kafka)

**Option A: Using mini-runtime in EKS (Recommended for Testing)**

```bash
# Install mini-runtime from Helm chart
helm install akto-mini-runtime ./charts/mini-runtime/ \
  -n default \
  --set mini_runtime.aktoApiSecurityRuntime.env.databaseAbstractorToken="$DATABASE_ABSTRACTOR_TOKEN"

# Wait for deployment
kubectl wait --for=condition=ready pod -l app=akto-mini-runtime -n default --timeout=300s

# Get the Kafka service endpoint
export AKTO_KAFKA_BROKER="akto-mini-runtime-mini-runtime.default.svc.cluster.local:9092"
echo "Kafka Broker: $AKTO_KAFKA_BROKER"
```

**Option B: Using Akto Cloud (Production)**

```bash
# Get your Akto cloud Kafka URL from the dashboard
export AKTO_KAFKA_BROKER="<YOUR_AKTO_CLOUD_KAFKA>:9092"
```

---

## Step 5: Deploy the API Gateway Logging Connector

### Option A: Using Helm Chart (Recommended)

The Helm chart is located at `helm-charts/charts/api-gateway-logging/`.

**Quick install with --set flags:**

```bash
helm install api-gateway-logging ./helm-charts/charts/api-gateway-logging/ \
  -n default \
  --set serviceAccount.annotations."eks\.amazonaws\.com/role-arn"="$IRSA_ROLE_ARN" \
  --set env.DATABASE_ABSTRACTOR_TOKEN="$DATABASE_ABSTRACTOR_TOKEN" \
  --set env.AWS_REGION="$EKS_REGION" \
  --set env.AKTO_KAFKA_BROKER_MAL="$AKTO_KAFKA_BROKER"
```

**Or create a custom values file** (`my-values.yaml`):

```yaml
serviceAccount:
  annotations:
    eks.amazonaws.com/role-arn: "arn:aws:iam::<EKS_ACCOUNT_ID>:role/EKSCloudWatchRole"

env:
  AWS_REGION: "ap-south-1"
  DATABASE_ABSTRACTOR_TOKEN: "<YOUR_TOKEN>"
  AKTO_KAFKA_BROKER_MAL: "akto-mini-runtime-mini-runtime.default.svc.cluster.local:9092"
  CROSS_ACCOUNT_ROLE_ARN: ""           # Leave empty for dynamic fetching
  DISCOVER_OPENAPI_SPEC: "true"
  OPENAPI_DISCOVERY_INTERVAL_MINUTES: "15"
```

Then install:

```bash
helm install api-gateway-logging ./helm-charts/charts/api-gateway-logging/ \
  -n default \
  -f my-values.yaml
```

**Upgrade an existing release:**

```bash
helm upgrade api-gateway-logging ./helm-charts/charts/api-gateway-logging/ \
  -n default \
  -f my-values.yaml
```

**Uninstall:**

```bash
helm uninstall api-gateway-logging -n default
```

### Option B: Using k8s-template.yml (Manual)

Update placeholders in `k8s-template.yml`:

- **Line 6**: `eks.amazonaws.com/role-arn` - Set to your IRSA role ARN
  - **MUST** use EKS account IRSA role: `arn:aws:iam::<EKS_ACCOUNT_ID>:role/EKSCloudWatchRole`
  - **DO NOT** use CloudWatch account role here
- **Line 40**: `CROSS_ACCOUNT_ROLE_ARN` - Leave empty for dynamic fetching, or set explicitly
- **Line 36**: `AKTO_KAFKA_BROKER_MAL` - Your Kafka broker endpoint
- **Line 46**: `AWS_REGION` - Your AWS region
- **Line 48**: `DATABASE_ABSTRACTOR_TOKEN` - Your token from Akto dashboard

Then apply:

```bash
kubectl apply -f k8s-template.yml
```

---

## Step 6: Verify Deployment

```bash
# Check pods
kubectl get pods -l app=api-gateway-logging

# Check logs
kubectl logs -f deployment/api-gateway-logging
```

**Expected log output:**
```
2026/02/17 15:30:00 Ticker interval set to 5 minutes
2026/02/17 15:30:00 OpenAPI spec discovery enabled with 15 minute interval
2026/02/17 15:30:01 Created CloudWatch Logs client for role: arn:aws:iam::...
2026/02/17 15:30:02 Starting OpenAPI discovery for role: arn:aws:iam::...
2026/02/17 15:30:03 Discovering REST APIs for role: arn:aws:iam::...
2026/02/17 15:30:04 Uploading OpenAPI spec for API: MyAPI to cyborg
2026/02/17 15:30:05 Successfully uploaded OpenAPI spec for API MyAPI
```

### Verify in Akto Dashboard

1. Login to Akto dashboard
2. Navigate to **API Inventory**
3. Wait 15-20 minutes for initial discovery
4. You should see:
   - APIs from CloudWatch logs (real traffic)
   - APIs from OpenAPI specs (all endpoints discovered from API Gateway)

---

## Environment Variables Reference

| Variable | Required | Default | Description |
|---|---|---|---|
| `DATABASE_ABSTRACTOR_TOKEN` | Yes | - | Auth token from Akto dashboard. Also used for OpenAPI spec upload to cyborg. |
| `AWS_REGION` | Yes | - | AWS region where API Gateway is deployed |
| `AKTO_KAFKA_BROKER_MAL` | Yes | - | Kafka broker endpoint for traffic logs |
| `CROSS_ACCOUNT_ROLE_ARN` | No | `""` | Cross-account role ARN. Leave empty for dynamic fetching via Akto API. |
| `DISCOVER_OPENAPI_SPEC` | No | `true` | Enable/disable OpenAPI spec discovery from API Gateway |
| `OPENAPI_DISCOVERY_INTERVAL_MINUTES` | No | `15` | Polling interval for OpenAPI discovery (minutes) |
| `LOG_GROUP_PREFIX` | No | `API-Gateway-Execution-Logs` | CloudWatch log group prefix to filter |
| `SESSION_NAME` | No | `aktologprocesser` | STS session name for role assumption |
| `AKTO_TRAFFIC_BATCH_SIZE` | No | `100` | Kafka batch size |
| `AKTO_TRAFFIC_BATCH_TIME_SECS` | No | `10` | Kafka batch time in seconds |
| `AKTO_BYTES_IN_THRESHOLD` | No | `100` | Bytes threshold for traffic filtering |
| `CLOUDWATCH_READ_BATCH_SIZE` | No | `5` | CloudWatch log read batch size |

**Note**: If `DATABASE_ABSTRACTOR_TOKEN` is not set, OpenAPI discovery is automatically disabled regardless of the `DISCOVER_OPENAPI_SPEC` value.

---

## Cleanup

**Helm:**
```bash
helm uninstall api-gateway-logging -n default
```

**kubectl:**
```bash
kubectl delete -f k8s-template.yml
```

**AWS resources:**
```bash
# Delete EKS cluster
eksctl delete cluster --name $EKS_CLUSTER_NAME --region $EKS_REGION

# Delete IRSA role (EKS account)
aws iam delete-role-policy --role-name EKSCloudWatchRole --policy-name AssumeCloudWatchRole
aws iam delete-role --role-name EKSCloudWatchRole

# Delete cross-account role (CloudWatch account)
aws iam detach-role-policy \
  --role-name CrossAccountCloudWatchRole \
  --policy-arn $CLOUDWATCH_POLICY_ARN
aws iam delete-role --role-name CrossAccountCloudWatchRole
aws iam delete-policy --policy-arn $CLOUDWATCH_POLICY_ARN
```

---

## Troubleshooting

### OIDC provider error: "No OpenIDConnect provider found in your account"
**Error message**: `WebIdentityErr: failed to retrieve credentials caused by: InvalidIdentityToken: No OpenIDConnect provider found in your account for https://oidc.eks...`

**Root cause**: Wrong IAM role ARN in ServiceAccount annotation

**Solution**:
- The ServiceAccount annotation MUST use the **EKS account IRSA role**, NOT the CloudWatch account cross-account role
- Correct: `eks.amazonaws.com/role-arn: "arn:aws:iam::<EKS_ACCOUNT_ID>:role/EKSCloudWatchRole"`
- Wrong: `eks.amazonaws.com/role-arn: "arn:aws:iam::<CLOUDWATCH_ACCOUNT_ID>:role/CrossAccountCloudWatchRole"`

**Verification**:
```bash
# Check OIDC provider exists
aws iam list-open-id-connect-providers

# Check role trust policy references correct OIDC provider
aws iam get-role --role-name EKSCloudWatchRole
```

### Pod fails to assume cross-account role
- Verify IRSA role ARN is correct in ServiceAccount annotation
- Check trust policy in cross-account role allows EKS account root to assume it
- Verify OIDC provider is correctly associated with EKS cluster
- Check pod logs for specific STS errors

### No CloudWatch logs appearing
- Ensure API Gateway has execution logging enabled
- Check `CROSS_ACCOUNT_ROLE_ARN` is correct (or left empty to use dynamic fetching)
- Verify cross-account role has `logs:*` permissions
- Check pod logs for role assumption errors

### No OpenAPI discovery
- Check `DISCOVER_OPENAPI_SPEC=true` in deployment
- Ensure `DATABASE_ABSTRACTOR_TOKEN` is set (required for OpenAPI upload)
- Verify cross-account role has `apigateway:GET` permission
- Check pod logs for "OpenAPI spec discovery enabled" message
- If you see "AKTO_TOKEN not set - disabling OpenAPI discovery", the `DATABASE_ABSTRACTOR_TOKEN` is missing

### OpenAPI spec upload failing
- Check pod logs for "cyborg API returned status" errors
- Verify `DATABASE_ABSTRACTOR_TOKEN` is valid and not expired
- Ensure the pod has network access to `https://cyborg.akto.io`

---

## Support

- Documentation: [Akto Docs](https://docs.akto.io)
- Issues: [GitHub Issues](https://github.com/akto-api-security/akto/issues)
- Project: [mirroring-api-logging](https://github.com/akto-api-security/mirroring-api-logging)
