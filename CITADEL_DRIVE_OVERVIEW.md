# Citadel Drive - Secure File Management System

## Overview

Citadel Drive is a comprehensive, enterprise-grade secure file management system built with Go 1.21+. It provides robust file storage, sharing, and collaboration capabilities with advanced security features including role-based access control (RBAC), end-to-end encryption, audit logging, and multi-factor authentication.

The system is designed for organizations that need to securely manage sensitive files while maintaining granular control over access permissions and maintaining comprehensive audit trails for compliance requirements.

## Core Features

### 🔐 Authentication & Security
- **JWT-based Authentication**: Secure token-based authentication system
- **Multi-Factor Authentication (MFA)**: TOTP-based 2FA with backup codes
- **Account Security**: Password hashing with bcrypt, account lockout protection
- **Session Management**: Secure session handling with IP tracking and user agent validation
- **Password Reset**: Secure token-based password reset functionality

### 👥 Role-Based Access Control (RBAC)
- **Hierarchical Permission System**: Five permission levels (read, write, update, delete, admin)
- **Organization Management**: Multi-tenant organization support
- **Role Assignment**: Admin, Owner, Editor, Viewer, Guest roles
- **Granular Permissions**: File and folder-level permission management
- **Permission Inheritance**: Automatic permission inheritance from parent folders

### 📁 File Operations
- **File Upload/Download**: Secure file transfer with multipart upload support
- **File Versioning**: Complete version history tracking
- **Folder Management**: Hierarchical folder structure
- **File Preview**: Support for various file types
- **File Sharing**: Secure file sharing with expiration dates
- **Storage Management**: Configurable storage limits and cleanup

### 🔒 Encryption & Security
- **File Encryption**: End-to-end encryption for sensitive files
- **Key Management**: Secure encryption key storage and rotation
- **Secure Storage**: Integration with Cloudflare R2 for secure object storage
- **Data Integrity**: Checksum validation for uploaded files

### 📊 Audit Logging
- **Comprehensive Tracking**: All user actions logged with timestamps
- **Security Events**: Failed login attempts, permission changes, file access
- **Compliance Support**: Detailed audit trails for regulatory compliance
- **Log Management**: Configurable log retention and filtering

### 🎛️ Admin Dashboard
- **User Management**: Complete user lifecycle management
- **Organization Administration**: Multi-tenant organization control
- **System Monitoring**: Health checks and performance metrics
- **Permission Oversight**: Centralized permission and role management

## Technology Stack

### Backend
- **Language**: Go 1.21+
- **Framework**: Gin Web Framework
- **Database**: PostgreSQL with GORM
- **Authentication**: JWT (golang-jwt/jwt/v5)
- **Security**: bcrypt, TOTP (pquerna/otp)

### Storage & Infrastructure
- **File Storage**: Cloudflare R2 (S3-compatible)
- **AWS SDK**: AWS SDK v2 for S3/R2 integration
- **Logging**: Uber Zap structured logging
- **Monitoring**: Prometheus metrics

### Development Tools
- **Database Migrations**: GORM AutoMigrate
- **Environment Management**: .env configuration
- **Container Support**: Docker ready
- **UUID Generation**: Google UUID package

## Database Schema

### Core Entities

#### Organization
```sql
- id: UUID (Primary Key)
- name: String (Indexed)
- created_at: Timestamp
- updated_at: Timestamp
```

#### User
```sql
- id: UUID (Primary Key)
- email: String (Unique, Indexed)
- password_hash: String
- full_name: String
- organization_id: UUID (Foreign Key)
- totp_secret: String (Nullable)
- totp_enabled: Boolean (Default: false)
- failed_login_attempts: Integer (Default: 0)
- locked_until: Timestamp (Nullable)
- is_active: Boolean (Default: true)
- created_at: Timestamp
- updated_at: Timestamp
```

#### File
```sql
- id: UUID (Primary Key)
- organization_id: UUID (Foreign Key)
- created_by: UUID (Foreign Key)
- folder_id: UUID (Foreign Key, Nullable)
- name: String
- original_name: String
- mime_type: String
- size: BigInt
- storage_path: String
- checksum: String
- is_encrypted: Boolean
- encryption_key_id: UUID (Nullable)
- is_deleted: Boolean (Default: false)
- deleted_at: Timestamp (Nullable)
- created_at: Timestamp
- updated_at: Timestamp
```

#### Folder
```sql
- id: UUID (Primary Key)
- organization_id: UUID (Foreign Key)
- created_by: UUID (Foreign Key)
- parent_folder_id: UUID (Foreign Key, Nullable)
- name: String
- path: String
- is_deleted: Boolean (Default: false)
- deleted_at: Timestamp (Nullable)
- created_at: Timestamp
- updated_at: Timestamp
```

#### Permission
```sql
- id: UUID (Primary Key)
- user_id: UUID (Foreign Key)
- file_id: UUID (Foreign Key, Nullable)
- folder_id: UUID (Foreign Key, Nullable)
- permission_type: String (Indexed)
- granted_by: UUID (Foreign Key, Nullable)
- expires_at: Timestamp (Nullable)
- created_at: Timestamp
```

#### UserPermission (Role Assignment)
```sql
- id: UUID (Primary Key)
- user_id: UUID (Foreign Key)
- organization_id: UUID (Foreign Key)
- role: String (Indexed)
- created_at: Timestamp
```

#### AuditLog
```sql
- id: UUID (Primary Key)
- user_id: UUID (Foreign Key, Nullable)
- action: String (Indexed)
- resource_type: String (Indexed)
- resource_id: UUID (Indexed)
- ip_address: String
- user_agent: Text
- metadata: JSONB
- created_at: Timestamp
```

## API Architecture

### Authentication Flow
1. **Registration/Login**: Email/password authentication
2. **MFA Verification**: TOTP validation when enabled
3. **JWT Generation**: Token issued with user and organization context
4. **Session Management**: Token validation and session tracking

### Request Processing Pipeline
1. **Middleware Stack**:
   - CORS handling
   - Request logging (Zap)
   - Authentication middleware
   - Permission validation
   - Rate limiting (configurable)

2. **Handler Processing**:
   - Input validation
   - Business logic execution
   - Database operations
   - Audit logging
   - Response formatting

### Response Format
All API responses follow a consistent format:
```json
{
  "success": true,
  "data": {...},
  "message": "Operation completed successfully",
  "timestamp": "2024-01-01T12:00:00Z"
}
```

## API Endpoints Overview

### Authentication Endpoints
- `POST /auth/register` - User registration
- `POST /auth/login` - User login
- `POST /auth/logout` - User logout
- `POST /auth/refresh` - Token refresh
- `POST /auth/forgot-password` - Password reset request
- `POST /auth/reset-password` - Password reset confirmation
- `POST /auth/setup-2fa` - Enable 2FA
- `POST /auth/verify-2fa` - Verify 2FA setup
- `GET /auth/backup-codes` - Generate backup codes

### File Management Endpoints
- `GET /files` - List files with pagination
- `POST /files/upload` - Upload single file
- `POST /files/upload-multipart` - Initialize multipart upload
- `PUT /files/upload-part/{sessionId}` - Upload file part
- `POST /files/complete-multipart/{sessionId}` - Complete multipart upload
- `GET /files/{id}` - Get file details
- `PUT /files/{id}` - Update file metadata
- `DELETE /files/{id}` - Delete file
- `GET /files/{id}/download` - Download file
- `GET /files/{id}/versions` - Get file versions
- `POST /files/{id}/restore/{versionId}` - Restore file version

### Folder Management Endpoints
- `GET /folders` - List folders
- `POST /folders` - Create folder
- `GET /folders/{id}` - Get folder details
- `PUT /folders/{id}` - Update folder
- `DELETE /folders/{id}` - Delete folder
- `GET /folders/{id}/contents` - Get folder contents

### Permission Management Endpoints
- `POST /permissions/grant` - Grant permission to user
- `DELETE /permissions/{id}` - Revoke permission
- `GET /permissions/file/{fileId}` - Get file permissions
- `GET /permissions/folder/{folderId}` - Get folder permissions
- `PUT /permissions/{id}` - Update permission
- `GET /permissions/user/{userId}` - Get user permissions

### Role Management Endpoints
- `GET /roles` - List available roles
- `POST /roles/assign` - Assign role to user
- `DELETE /roles/assign/{userId}` - Remove user role
- `GET /roles/organization/{organizationId}` - Get organization users

### Audit & Monitoring Endpoints
- `GET /audit/logs` - Get recent audit logs
- `GET /audit/resource/{resourceId}` - Get resource audit logs
- `GET /audit/user/{userId}` - Get user audit logs
- `GET /health` - Health check endpoint

### Admin Endpoints
- `GET /admin/users` - List users with pagination
- `POST /admin/users/{id}/activate` - Activate user
- `POST /admin/users/{id}/deactivate` - Deactivate user
- `POST /admin/users/{id}/lock` - Lock user account
- `POST /admin/users/{id}/unlock` - Unlock user account
- `GET /admin/organizations` - List organizations
- `GET /admin/stats` - System statistics

## Current Implementation Status

### ✅ Completed Features
- [x] User authentication and registration
- [x] JWT-based session management
- [x] TOTP 2FA implementation
- [x] Role-based access control (RBAC)
- [x] File upload and storage (R2 integration)
- [x] Multipart file uploads
- [x] File versioning system
- [x] Folder hierarchy management
- [x] Permission management (file/folder level)
- [x] Audit logging system
- [x] Database models and migrations
- [x] API endpoints implementation
- [x] Health check and monitoring
- [x] Encryption key management
- [x] Session tracking and blacklisting
- [x] Password reset functionality

### 🚧 In Progress / Planned Features
- [ ] File preview capabilities
- [ ] Advanced search functionality
- [ ] File sharing via public links
- [ ] Webhook notifications
- [ ] Advanced analytics dashboard
- [ ] API rate limiting implementation
- [ ] File watermarking
- [ ] Advanced encryption options
- [ ] File collaboration features
- [ ] Mobile application support

### 🔒 Security Features
- [x] Bcrypt password hashing
- [x] Account lockout protection
- [x] TOTP-based 2FA
- [x] JWT token security
- [x] Session management
- [x] IP address tracking
- [x] User agent validation
- [x] Password reset tokens
- [x] Encryption at rest
- [x] Audit trail compliance

## Security Highlights

### Authentication Security
- **Password Policy**: Strong password requirements enforced
- **Account Lockout**: Protection against brute force attacks
- **2FA Support**: TOTP-based two-factor authentication
- **Session Security**: Secure session handling with validation

### Data Protection
- **Encryption**: File encryption with secure key management
- **Secure Storage**: Cloudflare R2 for secure object storage
- **Data Integrity**: Checksum validation for file integrity
- **Access Control**: Granular permission system

### Audit & Compliance
- **Comprehensive Logging**: All user actions tracked
- **Security Events**: Failed login attempts and security events logged
- **Compliance Ready**: Audit trails suitable for regulatory compliance
- **IP Tracking**: All actions tracked with IP addresses and user agents

### Infrastructure Security
- **HTTPS Enforcement**: Secure communication required
- **CORS Configuration**: Proper cross-origin resource sharing setup
- **Input Validation**: Comprehensive input validation and sanitization
- **Error Handling**: Secure error handling without information leakage

## Use Cases

### Enterprise Document Management
- Secure document storage and sharing
- Role-based access to sensitive documents
- Audit trails for compliance requirements
- Version control for important documents

### Healthcare Data Management
- HIPAA-compliant file storage
- Patient record access control
- Audit logging for medical records
- Secure sharing between healthcare providers

### Legal Document Handling
- Attorney-client privilege protection
- Secure case file management
- Access control for legal teams
- Comprehensive audit trails

### Financial Services
- Secure financial document storage
- Compliance with financial regulations
- Multi-level access control
- Detailed audit logging

### Government & Defense
- Classified document management
- Multi-level security classifications
- Comprehensive security logging
- Secure inter-agency file sharing

## Project Statistics

### Code Metrics
- **Total Lines of Code**: ~15,000+ lines
- **Go Packages**: 8 core packages
- **API Endpoints**: 40+ endpoints
- **Database Models**: 12+ models
- **Middleware**: 5+ middleware components

### Dependencies
- **Direct Dependencies**: 12 core packages
- **Total Dependencies**: 80+ packages
- **Database**: PostgreSQL with GORM
- **Storage**: Cloudflare R2 (S3-compatible)
- **Authentication**: JWT with TOTP

### Performance Characteristics
- **Database**: Optimized with proper indexing
- **Storage**: Cloud-native object storage
- **Caching**: Configurable caching strategies
- **Monitoring**: Prometheus metrics integration
- **Logging**: Structured logging with Zap

### Deployment
- **Container Ready**: Docker support included
- **Environment**: Configurable via environment variables
- **Migration**: Automated database migrations
- **Health Checks**: Built-in health monitoring
- **Scalability**: Horizontal scaling capable

## Getting Started

### Prerequisites
- Go 1.21+
- PostgreSQL 12+
- Cloudflare R2 account (or S3-compatible storage)

### Installation
1. Clone the repository
2. Copy `.env.example` to `.env` and configure
3. Run database migrations: `go run ./cmd/migrate`
4. Start the API server: `go run ./cmd/api`

### Configuration
Key environment variables:
- `DATABASE_URL`: PostgreSQL connection string
- `JWT_SECRET`: JWT signing secret
- `R2_ENDPOINT`: Cloudflare R2 endpoint
- `R2_ACCESS_KEY_ID`: R2 access key
- `R2_SECRET_ACCESS_KEY`: R2 secret key

### API Documentation
- API Reference: `RBAC_API_REFERENCE.md`
- Implementation Guide: `RBAC_IMPLEMENTATION.md`
- Testing Guide: `RBAC_TESTING.md`

---

*Citadel Drive - Secure, Scalable, Enterprise-Grade File Management*