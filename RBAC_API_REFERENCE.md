# RBAC API Reference

## Overview

All permission and role endpoints require JWT authentication. Include the JWT token in the Authorization header:

```
Authorization: Bearer <JWT_TOKEN>
```

## Permission Endpoints

### Grant Permission to User
**Endpoint:** `POST /permissions/grant`

**Description:** Grant a permission to a user for a specific file or folder.

**Request Body:**
```json
{
  "user_id": "uuid",                    // Required: User to grant permission to
  "file_id": "uuid",                    // Optional: File ID (either file_id or folder_id required)
  "folder_id": "uuid",                  // Optional: Folder ID (either file_id or folder_id required)
  "permission_type": "read|write|update|delete|admin",  // Required
  "expires_at": "2024-12-31T23:59:59Z"  // Optional: Expiration timestamp
}
```

**Response (201 Created):**
```json
{
  "id": "uuid",
  "user_id": "uuid",
  "permission_type": "string",
  "expires_at": "timestamp|null",
  "created_at": "timestamp"
}
```

**Errors:**
- `400 Bad Request`: Invalid input (missing file_id/folder_id, invalid UUID)
- `403 Forbidden`: User doesn't have permission to grant (not admin/owner)
- `500 Internal Server Error`: Database error

---

### Revoke Permission
**Endpoint:** `DELETE /permissions/{id}`

**Description:** Remove a permission from a user.

**Path Parameters:**
- `id`: Permission UUID to revoke

**Response (200 OK):**
```json
{
  "message": "permission revoked"
}
```

**Errors:**
- `400 Bad Request`: Invalid permission ID
- `403 Forbidden`: User doesn't have permission to revoke
- `404 Not Found`: Permission not found
- `500 Internal Server Error`: Database error

---

### Get File Permissions
**Endpoint:** `GET /permissions/file/{fileId}`

**Description:** List all permissions for a specific file.

**Path Parameters:**
- `fileId`: File UUID

**Response (200 OK):**
```json
{
  "permissions": [
    {
      "id": "uuid",
      "user_id": "uuid",
      "permission_type": "string",
      "expires_at": "timestamp|null",
      "created_at": "timestamp",
      "granted_by": "uuid|null"
    }
  ]
}
```

**Errors:**
- `400 Bad Request`: Invalid file ID
- `500 Internal Server Error`: Database error

---

### Get Folder Permissions
**Endpoint:** `GET /permissions/folder/{folderId}`

**Description:** List all permissions for a specific folder.

**Path Parameters:**
- `folderId`: Folder UUID

**Response (200 OK):**
```json
{
  "permissions": [
    {
      "id": "uuid",
      "user_id": "uuid",
      "permission_type": "string",
      "expires_at": "timestamp|null",
      "created_at": "timestamp",
      "granted_by": "uuid|null"
    }
  ]
}
```

**Errors:**
- `400 Bad Request`: Invalid folder ID
- `500 Internal Server Error`: Database error

---

### Update Permission
**Endpoint:** `PUT /permissions/{id}`

**Description:** Update permission type or expiration date.

**Path Parameters:**
- `id`: Permission UUID

**Request Body:**
```json
{
  "permission_type": "read|write|update|delete|admin",  // Optional
  "expires_at": "2024-12-31T23:59:59Z"                  // Optional
}
```

**Response (200 OK):**
```json
{
  "id": "uuid",
  "permission_type": "string",
  "expires_at": "timestamp|null"
}
```

**Errors:**
- `400 Bad Request`: Invalid input
- `403 Forbidden`: User doesn't have permission to update
- `404 Not Found`: Permission not found
- `500 Internal Server Error`: Database error

---

### Get User Permissions
**Endpoint:** `GET /permissions/user/{userId}`

**Description:** List all permissions granted to a specific user.

**Path Parameters:**
- `userId`: User UUID

**Query Parameters:**
- `page` (default: 1): Page number
- `page_size` (default: 20, max: 100): Items per page

**Response (200 OK):**
```json
{
  "permissions": [
    {
      "id": "uuid",
      "file_id": "uuid|null",
      "folder_id": "uuid|null",
      "permission_type": "string",
      "expires_at": "timestamp|null",
      "created_at": "timestamp"
    }
  ],
  "pagination": {
    "page": 1,
    "page_size": 20,
    "total": 100
  }
}
```

**Errors:**
- `400 Bad Request`: Invalid user ID or pagination params
- `500 Internal Server Error`: Database error

---

## Role Endpoints

### List Available Roles
**Endpoint:** `GET /roles`

**Description:** Get all available roles with their associated permissions.

**Response (200 OK):**
```json
{
  "roles": [
    {
      "name": "Admin",
      "permissions": ["read", "write", "update", "delete", "admin"]
    },
    {
      "name": "Owner",
      "permissions": ["read", "write", "update", "delete", "admin"]
    },
    {
      "name": "Editor",
      "permissions": ["read", "write", "update"]
    },
    {
      "name": "Viewer",
      "permissions": ["read"]
    },
    {
      "name": "Guest",
      "permissions": []
    }
  ]
}
```

**Errors:**
- `500 Internal Server Error`: Database error

---

### Assign Role to User
**Endpoint:** `POST /roles/assign`

**Description:** Assign a role to a user in an organization.

**Request Body:**
```json
{
  "user_id": "uuid",              // Required: User to assign role to
  "organization_id": "uuid",      // Required: Organization
  "role": "Owner|Editor|Viewer|Guest|Admin"  // Required
}
```

**Response (201 Created):**
```json
{
  "id": "uuid",
  "user_id": "uuid",
  "organization_id": "uuid",
  "role": "string",
  "created_at": "timestamp"
}
```

**Errors:**
- `400 Bad Request`: Invalid input
- `403 Forbidden`: User doesn't have permission to assign roles
- `500 Internal Server Error`: Database error

---

### Remove User Role
**Endpoint:** `DELETE /roles/assign/{userId}`

**Description:** Remove a user's role from an organization.

**Path Parameters:**
- `userId`: User UUID

**Query Parameters:**
- `organization_id` (required): Organization UUID

**Response (200 OK):**
```json
{
  "message": "role removed"
}
```

**Errors:**
- `400 Bad Request`: Missing organization_id or invalid UUIDs
- `403 Forbidden`: User doesn't have permission to remove roles
- `500 Internal Server Error`: Database error

---

### Get Organization Users
**Endpoint:** `GET /roles/organization/{organizationId}`

**Description:** List all users and their roles in an organization.

**Path Parameters:**
- `organizationId`: Organization UUID

**Query Parameters:**
- `page` (default: 1): Page number
- `page_size` (default: 20, max: 100): Items per page

**Response (200 OK):**
```json
{
  "users": [
    {
      "id": "uuid",
      "user_id": "uuid",
      "organization_id": "uuid",
      "role": "string",
      "created_at": "timestamp"
    }
  ],
  "pagination": {
    "page": 1,
    "page_size": 20,
    "total": 50
  }
}
```

**Errors:**
- `400 Bad Request`: Invalid organization ID or pagination params
- `500 Internal Server Error`: Database error

---

## Audit Log Endpoints

### Get Recent Audit Logs
**Endpoint:** `GET /audit/logs`

**Description:** Get recent audit logs across the system.

**Query Parameters:**
- `limit` (default: 50, max: 200): Number of logs to return

**Response (200 OK):**
```json
{
  "logs": [
    {
      "id": "uuid",
      "user_id": "uuid|null",
      "action": "permission_granted|permission_revoked|permission_updated|role_assigned|...",
      "resource_type": "permission|role|file|folder|user",
      "resource_id": "uuid",
      "ip_address": "192.168.1.1",
      "user_agent": "Mozilla/5.0...",
      "metadata": {},
      "created_at": "timestamp"
    }
  ]
}
```

**Errors:**
- `500 Internal Server Error`: Database error

---

### Get Resource Audit Logs
**Endpoint:** `GET /audit/resource/{resourceId}`

**Description:** Get audit logs for a specific resource.

**Path Parameters:**
- `resourceId`: Resource UUID (file, folder, permission, etc.)

**Query Parameters:**
- `limit` (default: 50, max: 200): Number of logs
- `offset` (default: 0): Number of logs to skip

**Response (200 OK):**
```json
{
  "logs": [
    {
      "id": "uuid",
      "user_id": "uuid|null",
      "action": "string",
      "resource_type": "string",
      "resource_id": "uuid",
      "ip_address": "192.168.1.1",
      "user_agent": "string",
      "metadata": {},
      "created_at": "timestamp"
    }
  ]
}
```

**Errors:**
- `400 Bad Request`: Invalid resource ID
- `500 Internal Server Error`: Database error

---

### Get User Audit Logs
**Endpoint:** `GET /audit/user/{userId}`

**Description:** Get audit logs for actions performed by a specific user.

**Path Parameters:**
- `userId`: User UUID

**Query Parameters:**
- `limit` (default: 50, max: 200): Number of logs
- `offset` (default: 0): Number of logs to skip

**Response (200 OK):**
```json
{
  "logs": [
    {
      "id": "uuid",
      "user_id": "uuid",
      "action": "string",
      "resource_type": "string",
      "resource_id": "uuid",
      "ip_address": "192.168.1.1",
      "user_agent": "string",
      "metadata": {},
      "created_at": "timestamp"
    }
  ]
}
```

**Errors:**
- `400 Bad Request`: Invalid user ID or pagination params
- `500 Internal Server Error`: Database error

---

## Permission Types

### Hierarchy
Permissions follow a hierarchy where higher permissions include lower ones:

1. **read** (Level 1) - View/read resources
2. **write** (Level 2) - Create and edit content (includes read)
3. **update** (Level 3) - Modify existing content (includes read, write)
4. **delete** (Level 4) - Remove resources (includes read, write, update)
5. **admin** (Level 5) - Manage permissions and roles (includes all)

### Permission Inheritance
- When a user has a permission on a folder, they inherit that permission to all files in the folder
- Direct file permissions override folder permissions
- Permission checking is recursive up the folder hierarchy

---

## Common HTTP Status Codes

| Code | Meaning |
|------|---------|
| 200 | OK - Request successful |
| 201 | Created - Resource created successfully |
| 400 | Bad Request - Invalid input |
| 403 | Forbidden - Insufficient permissions |
| 404 | Not Found - Resource not found |
| 500 | Internal Server Error - Server error |
| 503 | Service Unavailable - Service temporarily unavailable |

---

## Authentication

All endpoints require JWT authentication. The token should be passed in the `Authorization` header:

```
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
```

The JWT token should include:
- `user_id`: UUID of the authenticated user
- `organization_id`: UUID of the user's organization
- `role`: User's role in the organization

---

## Rate Limiting

Currently, no rate limiting is implemented. Production deployments should consider adding rate limiting to prevent abuse.

---

## Pagination

For paginated endpoints, use `page` and `page_size` query parameters:
- `page`: Page number (default: 1, minimum: 1)
- `page_size`: Items per page (default: 20, maximum: 100)

Response includes pagination metadata:
```json
{
  "pagination": {
    "page": 1,
    "page_size": 20,
    "total": 150
  }
}
```

---

## Examples

### Grant Write Permission to a File
```bash
curl -X POST http://localhost:8080/permissions/grant \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": "550e8400-e29b-41d4-a716-446655440000",
    "file_id": "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
    "permission_type": "write"
  }'
```

### Grant Read Permission with Expiration
```bash
curl -X POST http://localhost:8080/permissions/grant \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": "550e8400-e29b-41d4-a716-446655440000",
    "folder_id": "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
    "permission_type": "read",
    "expires_at": "2024-12-31T23:59:59Z"
  }'
```

### Assign Admin Role
```bash
curl -X POST http://localhost:8080/roles/assign \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": "550e8400-e29b-41d4-a716-446655440000",
    "organization_id": "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
    "role": "Admin"
  }'
```

### List File Permissions
```bash
curl -X GET http://localhost:8080/permissions/file/6ba7b810-9dad-11d1-80b4-00c04fd430c8 \
  -H "Authorization: Bearer YOUR_TOKEN"
```

### Get Audit Logs for a Resource
```bash
curl -X GET "http://localhost:8080/audit/resource/6ba7b810-9dad-11d1-80b4-00c04fd430c8?limit=50&offset=0" \
  -H "Authorization: Bearer YOUR_TOKEN"
```
