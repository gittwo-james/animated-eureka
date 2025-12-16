# Role-Based Access Control (RBAC) Implementation Guide

This document describes the RBAC system implemented in Citadel Drive.

## Overview

The RBAC system provides granular permission management at both user and file/folder levels with the following key features:

- **5 Permission Levels**: read, write, update, delete, admin
- **5 User Roles**: Owner, Editor, Viewer, Guest, Admin
- **Permission Inheritance**: Folder permissions cascade to child files
- **Permission Expiration**: Automatic cleanup of expired permissions
- **Permission Caching**: 5-minute TTL cache for performance
- **Audit Logging**: Complete tracking of all permission changes

## Data Models

### Folder Model
```go
type Folder struct {
    ID             uuid.UUID
    ParentID       *uuid.UUID  // Support nested folders
    OwnerID        uuid.UUID
    OrganizationID uuid.UUID
    Name           string
    Description    string
    CreatedAt      time.Time
    UpdatedAt      time.Time
    DeletedAt      gorm.DeletedAt
}
```

### File Model (Updated)
```go
type File struct {
    // ... existing fields ...
    FolderID       *uuid.UUID  // New field for folder organization
    // ... rest of fields ...
}
```

### Permission Model (Enhanced)
```go
type Permission struct {
    ID             uuid.UUID
    UserID         uuid.UUID   // User who has the permission
    FileID         *uuid.UUID  // File-level permission
    FolderID       *uuid.UUID  // Folder-level permission
    PermissionType string      // read, write, update, delete, admin
    GrantedBy      *uuid.UUID  // User who granted this permission
    ExpiresAt      *time.Time  // Permission expiration date
    CreatedAt      time.Time
    UpdatedAt      time.Time
}
```

### UserPermission Model (Role Assignment)
```go
type UserPermission struct {
    ID             uuid.UUID
    UserID         uuid.UUID
    OrganizationID uuid.UUID
    Role           string      // Owner, Editor, Viewer, Guest, Admin
    CreatedAt      time.Time
}
```

### AuditLog Model (for tracking changes)
```go
type AuditLog struct {
    ID           uuid.UUID
    UserID       *uuid.UUID
    Action       string      // permission_granted, permission_revoked, etc.
    ResourceType string      // permission, role, file, folder
    ResourceID   uuid.UUID
    IPAddress    string
    UserAgent    string
    Metadata     datatypes.JSON
    CreatedAt    time.Time
}
```

## Permission Hierarchy

Permissions are hierarchical - higher levels include lower permissions:

```
admin (level 5)
  ├── delete (level 4)
  │   ├── update (level 3)
  │   │   ├── write (level 2)
  │   │   │   └── read (level 1)
```

This means:
- A user with "admin" permission can perform all operations
- A user with "delete" permission can read, write, update, and delete
- A user with "write" permission can read and write
- A user with "read" permission can only read

## Role Definitions

### Owner
- Full control over organization and resources
- Can manage all permissions and roles
- Default role for organization creator
- Permissions: read, write, update, delete, admin

### Admin
- Administrative control within organization
- Can manage permissions and roles
- Permissions: read, write, update, delete, admin

### Editor
- Can create, edit, and modify content
- Cannot delete items or manage permissions
- Permissions: read, write, update

### Viewer
- Read-only access
- Cannot modify or delete content
- Permissions: read

### Guest
- Minimal or no permissions
- Used for temporary or public sharing
- Permissions: (none)

## Repositories

### PermissionRepository
Handles all permission-related operations:
- `GrantPermission()`: Grant a new permission
- `RevokePermission()`: Remove a permission
- `GetUserPermissionForFile()`: Get permission for specific file
- `GetUserPermissionForFolder()`: Get permission for specific folder
- `GetFilePermissions()`: Get all permissions for a file
- `GetFolderPermissions()`: Get all permissions for a folder
- `GetUserPermissions()`: Get all permissions for a user
- `UpdatePermission()`: Update permission type or expiration
- `InvalidateExpiredPermissions()`: Cleanup expired permissions
- `CheckUserCanAccessFile()`: Check if user can access file
- `CheckUserCanAccessFolder()`: Check if user can access folder (with inheritance)

### RoleRepository
Handles role assignment and checking:
- `AssignRole()`: Assign role to user in organization
- `GetUserRole()`: Get user's role
- `GetOrganizationUsers()`: Get all users in organization
- `RemoveUserRole()`: Remove user's role
- `GetAvailableRoles()`: List all available roles
- `GetRolePermissions()`: Get permissions for a role
- `CanUserManagePermissions()`: Check if user is admin/owner

### PermissionCache
In-memory cache with 5-minute TTL for performance:
- `Get()`: Retrieve cached file permission
- `GetFolder()`: Retrieve cached folder permission
- `Set()`: Cache a permission
- `SetFolder()`: Cache folder permission
- `SetNegative()`: Cache "no permission" result
- `SetFolderNegative()`: Cache "no folder permission" result
- `InvalidateUser()`: Clear cache for user
- `InvalidateFile()`: Clear cache for file
- `InvalidateFolder()`: Clear cache for folder
- `Clear()`: Clear entire cache

### AuditRepository
Tracks all permission and role changes:
- `LogAction()`: Log a general action
- `LogPermissionGranted()`: Log permission grant
- `LogPermissionRevoked()`: Log permission revocation
- `LogPermissionUpdated()`: Log permission update
- `LogRoleAssigned()`: Log role assignment
- `LogFileAccessed()`: Log file access
- `LogFolderAccessed()`: Log folder access
- `GetAuditLogs()`: Get audit logs for resource
- `GetUserAuditLogs()`: Get audit logs by user
- `GetRecentAuditLogs()`: Get recent audit logs

## Middleware

### Permission Checking Middleware
- `RequireFilePermission()`: Check permission for file access
- `RequireFolderPermission()`: Check permission for folder access
- Helper functions for extracting user ID and IP from requests

### Auth Middleware (Enhanced)
- `RequireAnyRole()`: Check if user has any of specified roles

## API Endpoints

### Permission Endpoints

#### Grant Permission
```
POST /permissions/grant
Body: {
  "user_id": "uuid",
  "file_id": "uuid" OR "folder_id": "uuid",
  "permission_type": "read|write|update|delete|admin",
  "expires_at": "2024-12-31T23:59:59Z" (optional)
}
Response: {
  "id": "uuid",
  "user_id": "uuid",
  "permission_type": "string",
  "expires_at": "timestamp",
  "created_at": "timestamp"
}
```

#### Revoke Permission
```
DELETE /permissions/{id}
Response: { "message": "permission revoked" }
```

#### Get File Permissions
```
GET /permissions/file/{fileId}
Response: {
  "permissions": [
    {
      "id": "uuid",
      "user_id": "uuid",
      "permission_type": "string",
      "expires_at": "timestamp",
      "created_at": "timestamp",
      "granted_by": "uuid"
    }
  ]
}
```

#### Get Folder Permissions
```
GET /permissions/folder/{folderId}
Response: {
  "permissions": [...]
}
```

#### Update Permission
```
PUT /permissions/{id}
Body: {
  "permission_type": "string" (optional),
  "expires_at": "timestamp" (optional)
}
Response: {
  "id": "uuid",
  "permission_type": "string",
  "expires_at": "timestamp"
}
```

#### Get User Permissions
```
GET /permissions/user/{userId}?page=1&page_size=20
Response: {
  "permissions": [...],
  "pagination": {
    "page": 1,
    "page_size": 20,
    "total": 100
  }
}
```

### Role Endpoints

#### List Available Roles
```
GET /roles
Response: {
  "roles": [
    {
      "name": "Admin",
      "permissions": ["read", "write", "update", "delete", "admin"]
    }
  ]
}
```

#### Assign Role
```
POST /roles/assign
Body: {
  "user_id": "uuid",
  "organization_id": "uuid",
  "role": "Owner|Editor|Viewer|Guest|Admin"
}
Response: {
  "id": "uuid",
  "user_id": "uuid",
  "organization_id": "uuid",
  "role": "string",
  "created_at": "timestamp"
}
```

#### Remove Role
```
DELETE /roles/assign/{userId}?organization_id=uuid
Response: { "message": "role removed" }
```

#### Get Organization Users
```
GET /roles/organization/{organizationId}?page=1&page_size=20
Response: {
  "users": [...],
  "pagination": { ... }
}
```

### Audit Log Endpoints

#### Get Recent Audit Logs
```
GET /audit/logs?limit=50
Response: {
  "logs": [
    {
      "id": "uuid",
      "user_id": "uuid",
      "action": "permission_granted",
      "resource_type": "permission",
      "resource_id": "uuid",
      "ip_address": "127.0.0.1",
      "user_agent": "string",
      "metadata": {},
      "created_at": "timestamp"
    }
  ]
}
```

#### Get Resource Audit Logs
```
GET /audit/resource/{resourceId}?limit=50&offset=0
Response: { "logs": [...] }
```

#### Get User Audit Logs
```
GET /audit/user/{userId}?limit=50&offset=0
Response: { "logs": [...] }
```

## Permission Inheritance

File permissions inherit from folder permissions:

```
Folder A (read permission for User X)
  └── File B (no direct permission)
       → User X can read File B (via folder inheritance)

Folder A (read permission for User X)
  └── Folder C (read permission for User X)
       └── File D (no direct permission)
           → User X can read File D (via folder inheritance)
```

Direct file permissions override folder permissions if they're more restrictive.

## Permission Expiration

Permissions can have optional expiration dates:
- When checking permissions, expired permissions are ignored
- A background job runs every hour to clean up expired permissions
- Jobs uses `InvalidateExpiredPermissions()` to delete expired records

## Permission Caching

The system uses an in-memory cache with 5-minute TTL:
- Improves performance by reducing database queries
- Cache is invalidated when permissions are modified
- User-scoped invalidation available
- File and folder level invalidation available

## Authorization Rules

1. **Owner Check**: File/folder owner has all permissions
2. **Direct Permission**: Check if user has direct permission on file/folder
3. **Inheritance**: Check parent folder permissions recursively
4. **Privilege Escalation Prevention**: 
   - Only admins and owners can grant permissions
   - Role changes are logged in audit trail
5. **Expiration Enforcement**: Expired permissions are treated as non-existent

## Security Considerations

1. **Authentication**: All permission endpoints require JWT authentication
2. **Authorization**: Only authenticated users can be granted permissions
3. **Audit Trail**: All permission changes are logged with:
   - Who made the change
   - What changed
   - When it changed
   - Where it came from (IP address)
   - What user agent was used
4. **Cache Expiration**: Cache expires after 5 minutes to detect permission changes
5. **Privilege Management**: Only owners and admins can manage permissions

## Database Migrations

Migrations are automatic via GORM's AutoMigrate:
```
models.Organization
models.User
models.Folder (new)
models.File
models.FileVersion
models.Permission (updated)
models.UserPermission (existing)
models.AuditLog (existing)
models.Session
models.TokenBlacklist
models.UserBackupCode
models.EncryptionKey
models.SharedToken
models.FileTag
models.IPBlacklist
```

## Integration Points

The RBAC system integrates with:
- **JWT Auth Middleware**: For user authentication
- **Gin Router**: For HTTP endpoint handling
- **GORM/Postgres**: For data persistence
- **Zap Logger**: For application logging
- **Audit System**: For compliance tracking

## Example Workflows

### Granting Read Access to a File
```
1. User A (admin) calls POST /permissions/grant
2. System checks User A has admin/owner role
3. System creates Permission record
4. System logs to AuditLog
5. System invalidates cache
6. Permission is immediately available
```

### Accessing a File
```
1. User B tries to access File X
2. System checks JWT token (already authenticated)
3. System checks cache for User B's permission on File X
4. If not cached:
   a. Check direct permission on File X
   b. If not found, check parent Folder's permissions recursively
   c. Cache the result
5. Grant or deny access
```

### Permission Expiration
```
1. Background job runs every hour
2. Calls InvalidateExpiredPermissions()
3. Deletes all Permission records where ExpiresAt <= now()
4. On next access, expired permissions are no longer available
```
