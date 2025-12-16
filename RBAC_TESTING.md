# RBAC Testing Guide

## Prerequisites

1. API server running with JWT authentication enabled
2. Valid JWT token with admin/owner role
3. Postgres database with migrations applied
4. cURL or HTTP client tool

## Test Scenarios

### 1. Basic Permission Grant

```bash
# Grant read permission on a file
curl -X POST http://localhost:8080/permissions/grant \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": "USER_ID_UUID",
    "file_id": "FILE_ID_UUID",
    "permission_type": "read"
  }'

# Expected Response (201 Created):
{
  "id": "PERMISSION_ID",
  "user_id": "USER_ID_UUID",
  "permission_type": "read",
  "expires_at": null,
  "created_at": "2024-01-01T12:00:00Z"
}
```

### 2. Permission with Expiration

```bash
# Grant permission that expires in 24 hours
curl -X POST http://localhost:8080/permissions/grant \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": "USER_ID_UUID",
    "file_id": "FILE_ID_UUID",
    "permission_type": "write",
    "expires_at": "2024-01-02T12:00:00Z"
  }'
```

### 3. Folder Permission (Inheritance)

```bash
# Grant permission on a folder (applies to all child files)
curl -X POST http://localhost:8080/permissions/grant \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": "USER_ID_UUID",
    "folder_id": "FOLDER_ID_UUID",
    "permission_type": "read"
  }'
```

### 4. List Permissions

```bash
# List all permissions for a file
curl -X GET http://localhost:8080/permissions/file/FILE_ID_UUID \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"

# List all permissions for a folder
curl -X GET http://localhost:8080/permissions/folder/FOLDER_ID_UUID \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"

# List all permissions for a user
curl -X GET "http://localhost:8080/permissions/user/USER_ID_UUID?page=1&page_size=20" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

### 5. Update Permission

```bash
# Change permission type
curl -X PUT http://localhost:8080/permissions/PERMISSION_ID \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "permission_type": "write"
  }'

# Update expiration date
curl -X PUT http://localhost:8080/permissions/PERMISSION_ID \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "expires_at": "2024-02-01T12:00:00Z"
  }'
```

### 6. Revoke Permission

```bash
curl -X DELETE http://localhost:8080/permissions/PERMISSION_ID \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"

# Expected Response (200 OK):
{ "message": "permission revoked" }
```

### 7. Role Management

```bash
# List available roles
curl -X GET http://localhost:8080/roles \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"

# Assign role to user
curl -X POST http://localhost:8080/roles/assign \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": "USER_ID_UUID",
    "organization_id": "ORG_ID_UUID",
    "role": "Editor"
  }'

# Get organization users
curl -X GET "http://localhost:8080/roles/organization/ORG_ID_UUID?page=1&page_size=20" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"

# Remove role
curl -X DELETE "http://localhost:8080/roles/assign/USER_ID_UUID?organization_id=ORG_ID_UUID" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

### 8. Audit Logs

```bash
# Get recent audit logs
curl -X GET "http://localhost:8080/audit/logs?limit=50" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"

# Get audit logs for a resource
curl -X GET "http://localhost:8080/audit/resource/RESOURCE_ID?limit=50&offset=0" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"

# Get audit logs for a user
curl -X GET "http://localhost:8080/audit/user/USER_ID?limit=50&offset=0" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

## Permission Inheritance Test

```bash
# Setup:
# 1. Create Folder A
# 2. Create File B in Folder A
# 3. Grant read permission on Folder A to User X

# Test: User X should be able to read File B
# - File B has no direct permission for User X
# - But Folder A has read permission for User X
# - File B should inherit the permission
```

## Permission Expiration Test

```bash
# Setup:
# 1. Grant permission with expires_at = now() - 1 minute

# Test: Permission should not be usable
# - Permission should be ignored in access checks
# - After 1 hour, background job should delete it from database
```

## Permission Hierarchy Test

```bash
# Setup:
# 1. Grant "write" permission to User A on File X

# Test: User A should be able to:
# ✓ Read File X (write includes read)
# ✓ Write to File X
# ✗ Update File X (write doesn't include update)
# ✗ Delete File X (write doesn't include delete)

# Test 2:
# Grant "admin" permission to User B on File X

# User B should be able to:
# ✓ Read File X
# ✓ Write to File X
# ✓ Update File X
# ✓ Delete File X
# ✓ Manage permissions on File X
```

## Caching Test

```bash
# Setup:
# 1. Grant permission to User X on File A
# 2. Call endpoint to check permission (should cache result)
# 3. Call endpoint again immediately (should use cache)

# Expected behavior:
# - First call hits database
# - Second call uses cache (faster)
# - Cache expires after 5 minutes
# - After 5 minutes, next call hits database again

# Test invalidation:
# 1. Grant permission (cached)
# 2. Update permission (cache invalidated)
# 3. Next check should hit database
```

## Error Cases

### Invalid Permission Type
```bash
curl -X POST http://localhost:8080/permissions/grant \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": "USER_ID_UUID",
    "file_id": "FILE_ID_UUID",
    "permission_type": "invalid"
  }'

# Expected: 400 Bad Request (or permission creation fails)
```

### Missing File and Folder ID
```bash
curl -X POST http://localhost:8080/permissions/grant \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": "USER_ID_UUID",
    "permission_type": "read"
  }'

# Expected: 400 Bad Request
# { "error": "either file_id or folder_id required" }
```

### Insufficient Permissions
```bash
# Try to grant permission as non-admin user
curl -X POST http://localhost:8080/permissions/grant \
  -H "Authorization: Bearer EDITOR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{...}'

# Expected: 403 Forbidden
# { "error": "insufficient permissions to grant" }
```

### Invalid User ID
```bash
curl -X POST http://localhost:8080/permissions/grant \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": "not-a-uuid",
    "file_id": "FILE_ID_UUID",
    "permission_type": "read"
  }'

# Expected: 400 Bad Request
# { "error": "invalid user_id" }
```

## Performance Testing

### Cache Effectiveness
```bash
# Without cache (baseline):
# 100 permission checks = 100 database queries

# With cache:
# First check: 1 database query (cached)
# Next 99 checks (within 5 min): 0 database queries (from cache)
# After 5 min: 1 database query (cache expired)
```

### Concurrent Requests
```bash
# Test multiple concurrent permission grants
ab -n 100 -c 10 -X POST \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{}' \
  http://localhost:8080/permissions/grant
```

## Database State Verification

```sql
-- Check permissions table
SELECT id, user_id, file_id, folder_id, permission_type, expires_at
FROM permissions
WHERE user_id = 'USER_UUID'
ORDER BY created_at DESC;

-- Check role assignments
SELECT id, user_id, role
FROM user_permissions
WHERE user_id = 'USER_UUID';

-- Check audit logs
SELECT id, user_id, action, resource_type, created_at
FROM audit_logs
WHERE resource_id = 'RESOURCE_UUID'
ORDER BY created_at DESC;

-- Check expired permissions (should be empty after cleanup job runs)
SELECT id FROM permissions
WHERE expires_at IS NOT NULL AND expires_at <= NOW();
```

## Integration Testing

### Complete Permission Grant Flow
1. User authenticates and gets JWT token
2. User is assigned "Admin" role
3. Admin grants "write" permission to another user on a file
4. Permission is created in database
5. Audit log entry is created
6. Cache is populated
7. New user can now access the file with write permission
8. Admin can update the permission later
9. Admin can revoke the permission
10. New user can no longer access the file

### Permission Expiration Flow
1. Grant permission with 5-minute expiration
2. Verify permission works immediately
3. Wait 5 minutes
4. Verify permission is still in database
5. Background job runs (every hour)
6. After job runs, permission is deleted
7. User can no longer access the file

## Monitoring

Monitor these metrics for health:
- Cache hit ratio (higher is better)
- Permission check latency (should be <10ms with cache)
- Audit log entries (growing steadily)
- Expired permission cleanup job execution
