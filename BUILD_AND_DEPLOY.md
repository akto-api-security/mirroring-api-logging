# Build and Deploy Updated Docker Image

## Prerequisites
- Docker installed locally
- AWS CLI configured
- kubectl configured for your EKS cluster

## Step 1: Create ECR Repository (One-time setup)

```bash
# Set variables
export AWS_REGION="ap-south-1"
export ECR_REPO_NAME="akto-api-gateway-logging"

# Create ECR repository
aws ecr create-repository \
  --repository-name $ECR_REPO_NAME \
  --region $AWS_REGION

# Get the repository URI
export ECR_REPO_URI=$(aws ecr describe-repositories \
  --repository-names $ECR_REPO_NAME \
  --region $AWS_REGION \
  --query 'repositories[0].repositoryUri' \
  --output text)

echo "ECR Repository URI: $ECR_REPO_URI"
```

## Step 2: Build and Push Docker Image

```bash
# Navigate to project directory
cd /Users/tangobee/Documents/mirroring-api-logging

# Authenticate Docker to ECR
aws ecr get-login-password --region $AWS_REGION | \
  docker login --username AWS --password-stdin ${ECR_REPO_URI%/*}

# Build the image (supports both amd64 and arm64)
docker build --platform linux/amd64 -t $ECR_REPO_NAME:latest .

# Tag the image
docker tag $ECR_REPO_NAME:latest $ECR_REPO_URI:latest
docker tag $ECR_REPO_NAME:latest $ECR_REPO_URI:v1.0.0-openapi

# Push to ECR
docker push $ECR_REPO_URI:latest
docker push $ECR_REPO_URI:v1.0.0-openapi

echo "Image pushed successfully: $ECR_REPO_URI:latest"
```

## Step 3: Update Kubernetes Manifest

```bash
# Update k8s-template.yml with your ECR image
# Replace the image line with your ECR URI
sed -i.bak "s|aktosecurity/mirror-api-logging:api-gateway-logging|$ECR_REPO_URI:latest|g" k8s-template.yml

# Or manually edit k8s-template.yml and change:
# image: aktosecurity/mirror-api-logging:api-gateway-logging
# to:
# image: <YOUR_ECR_URI>:latest
```

## Step 4: Deploy to EKS

```bash
# Apply the updated manifest
kubectl apply -f k8s-template.yml

# Check deployment status
kubectl get pods -l app=api-gateway-logging

# Check logs for the new pod
kubectl logs -f deployment/api-gateway-logging
```

## Expected Log Output

You should see logs like:
```
2026/02/17 15:30:00 Ticker interval set to 5 minutes
2026/02/17 15:30:00 OpenAPI spec discovery enabled with 15 minute interval
2026/02/17 15:30:01 Created CloudWatch Logs client for role: arn:aws:iam::...
2026/02/17 15:30:02 Created API Gateway clients (REST + HTTP) for role: arn:aws:iam::...
2026/02/17 15:30:03 Starting OpenAPI discovery for role: arn:aws:iam::...
2026/02/17 15:30:04 Discovering REST APIs for role: arn:aws:iam::...
```

## Quick Commands Reference

```bash
# Rebuild and redeploy (after code changes)
docker build --platform linux/amd64 -t $ECR_REPO_NAME:latest . && \
docker tag $ECR_REPO_NAME:latest $ECR_REPO_URI:latest && \
docker push $ECR_REPO_URI:latest && \
kubectl rollout restart deployment/api-gateway-logging

# Check pod status
kubectl get pods -l app=api-gateway-logging -w

# View logs
kubectl logs -f deployment/api-gateway-logging

# Check if mini-runtime is running
kubectl get pods -l app=akto-mini-runtime

# Test Kafka connectivity from the pod
kubectl exec -it deployment/api-gateway-logging -- sh
# Inside the pod:
# nc -zv akto-mini-runtime-mini-runtime.default.svc.cluster.local 9092
```
