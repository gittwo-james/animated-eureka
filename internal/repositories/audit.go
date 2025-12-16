package repositories

import (
	"citadel-drive/internal/models"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

const (
	ActionPermissionGranted    = "permission_granted"
	ActionPermissionRevoked    = "permission_revoked"
	ActionPermissionUpdated    = "permission_updated"
	ActionRoleAssigned         = "role_assigned"
	ActionRoleRemoved          = "role_removed"
	ActionFileAccessed         = "file_accessed"
	ActionFolderAccessed       = "folder_accessed"
	ActionFileCreated          = "file_created"
	ActionFileDeleted          = "file_deleted"
	ActionFolderCreated        = "folder_created"
	ActionFolderDeleted        = "folder_deleted"
)

const (
	ResourceTypePermission = "permission"
	ResourceTypeRole       = "role"
	ResourceTypeFile       = "file"
	ResourceTypeFolder     = "folder"
	ResourceTypeUser       = "user"
)

type AuditRepository struct {
	db *gorm.DB
}

func NewAuditRepository(db *gorm.DB) *AuditRepository {
	return &AuditRepository{db: db}
}

// LogAction logs an audit action
func (r *AuditRepository) LogAction(
	userID *uuid.UUID,
	action string,
	resourceType string,
	resourceID uuid.UUID,
	ipAddress string,
	userAgent string,
	metadata interface{},
) error {
	var metadataJSON datatypes.JSON
	if metadata != nil {
		jsonData, err := json.Marshal(metadata)
		if err != nil {
			return err
		}
		metadataJSON = jsonData
	}

	auditLog := &models.AuditLog{
		ID:           uuid.New(),
		UserID:       userID,
		Action:       action,
		ResourceType: resourceType,
		ResourceID:   resourceID,
		IPAddress:    ipAddress,
		UserAgent:    userAgent,
		Metadata:     metadataJSON,
		CreatedAt:    time.Now(),
	}

	return r.db.Create(auditLog).Error
}

// LogPermissionGranted logs when a permission is granted
func (r *AuditRepository) LogPermissionGranted(
	grantedBy *uuid.UUID,
	grantedTo uuid.UUID,
	resourceID uuid.UUID,
	permissionType string,
	isFolder bool,
	ipAddress string,
	userAgent string,
) error {
	metadata := map[string]interface{}{
		"granted_to":       grantedTo.String(),
		"permission_type":  permissionType,
		"is_folder":        isFolder,
	}

	return r.LogAction(grantedBy, ActionPermissionGranted, ResourceTypePermission, resourceID, ipAddress, userAgent, metadata)
}

// LogPermissionRevoked logs when a permission is revoked
func (r *AuditRepository) LogPermissionRevoked(
	revokedBy *uuid.UUID,
	resourceID uuid.UUID,
	ipAddress string,
	userAgent string,
) error {
	return r.LogAction(revokedBy, ActionPermissionRevoked, ResourceTypePermission, resourceID, ipAddress, userAgent, nil)
}

// LogPermissionUpdated logs when a permission is updated
func (r *AuditRepository) LogPermissionUpdated(
	updatedBy *uuid.UUID,
	permissionID uuid.UUID,
	oldPermission string,
	newPermission string,
	ipAddress string,
	userAgent string,
) error {
	metadata := map[string]interface{}{
		"old_permission": oldPermission,
		"new_permission": newPermission,
	}

	return r.LogAction(updatedBy, ActionPermissionUpdated, ResourceTypePermission, permissionID, ipAddress, userAgent, metadata)
}

// LogRoleAssigned logs when a role is assigned
func (r *AuditRepository) LogRoleAssigned(
	assignedBy *uuid.UUID,
	userID uuid.UUID,
	role string,
	organizationID uuid.UUID,
	ipAddress string,
	userAgent string,
) error {
	metadata := map[string]interface{}{
		"user_id":         userID.String(),
		"role":            role,
		"organization_id": organizationID.String(),
	}

	return r.LogAction(assignedBy, ActionRoleAssigned, ResourceTypeRole, organizationID, ipAddress, userAgent, metadata)
}

// LogFileAccessed logs when a file is accessed
func (r *AuditRepository) LogFileAccessed(
	userID *uuid.UUID,
	fileID uuid.UUID,
	ipAddress string,
	userAgent string,
) error {
	return r.LogAction(userID, ActionFileAccessed, ResourceTypeFile, fileID, ipAddress, userAgent, nil)
}

// LogFolderAccessed logs when a folder is accessed
func (r *AuditRepository) LogFolderAccessed(
	userID *uuid.UUID,
	folderID uuid.UUID,
	ipAddress string,
	userAgent string,
) error {
	return r.LogAction(userID, ActionFolderAccessed, ResourceTypeFolder, folderID, ipAddress, userAgent, nil)
}

// GetAuditLogs retrieves audit logs for a resource
func (r *AuditRepository) GetAuditLogs(resourceID uuid.UUID, limit int, offset int) ([]models.AuditLog, error) {
	var logs []models.AuditLog
	err := r.db.Where("resource_id = ?", resourceID).
		Order("created_at DESC").
		Limit(limit).
		Offset(offset).
		Find(&logs).Error
	return logs, err
}

// GetUserAuditLogs retrieves audit logs for actions performed by a user
func (r *AuditRepository) GetUserAuditLogs(userID uuid.UUID, limit int, offset int) ([]models.AuditLog, error) {
	var logs []models.AuditLog
	err := r.db.Where("user_id = ?", userID).
		Order("created_at DESC").
		Limit(limit).
		Offset(offset).
		Find(&logs).Error
	return logs, err
}

// GetRecentAuditLogs retrieves recent audit logs
func (r *AuditRepository) GetRecentAuditLogs(limit int) ([]models.AuditLog, error) {
	var logs []models.AuditLog
	err := r.db.Order("created_at DESC").Limit(limit).Find(&logs).Error
	return logs, err
}
