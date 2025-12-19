package repositories

import (
	"encoding/json"

	"citadel-drive/internal/models"

	"github.com/google/uuid"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

type AuditRepository struct {
	DB *gorm.DB
}

func NewAuditRepository(db *gorm.DB) *AuditRepository {
	return &AuditRepository{DB: db}
}

func (r *AuditRepository) Log(userID *uuid.UUID, action, resourceType string, resourceID uuid.UUID, ip, userAgent string, metadata map[string]interface{}) error {
	var metaBytes []byte
	var err error
	if metadata != nil {
		metaBytes, err = json.Marshal(metadata)
		if err != nil {
			return err
		}
	}
	logEntry := models.AuditLog{
		UserID:       userID,
		Action:       action,
		ResourceType: resourceType,
		ResourceID:   resourceID,
		IPAddress:    ip,
		UserAgent:    userAgent,
		Metadata:     datatypes.JSON(metaBytes),
	}
	return r.DB.Create(&logEntry).Error
}

func (r *AuditRepository) List(filter map[string]interface{}, limit, offset int) ([]models.AuditLog, int64, error) {
	var logs []models.AuditLog
	var total int64

	query := r.DB.Model(&models.AuditLog{})

	// Apply filters
	if uid, ok := filter["user_id"]; ok {
		query = query.Where("user_id = ?", uid)
	}
	if act, ok := filter["action"]; ok {
		query = query.Where("action = ?", act)
	}
	if resType, ok := filter["resource_type"]; ok {
		query = query.Where("resource_type = ?", resType)
	}
	if resID, ok := filter["resource_id"]; ok {
		query = query.Where("resource_id = ?", resID)
	}
	// Add date range filters if needed, etc.

	err := query.Count(&total).Error
	if err != nil {
		return nil, 0, err
	}

	err = query.Order("created_at desc").Limit(limit).Offset(offset).Find(&logs).Error
	if err != nil {
		return nil, 0, err
	}

	return logs, total, nil
}

func (r *AuditRepository) GetByUserID(userID uuid.UUID, limit, offset int) ([]models.AuditLog, error) {
	var logs []models.AuditLog
	err := r.DB.Where("user_id = ?", userID).Order("created_at desc").Limit(limit).Offset(offset).Find(&logs).Error
	return logs, err
}

func (r *AuditRepository) GetByResourceID(resourceID uuid.UUID, limit, offset int) ([]models.AuditLog, error) {
	var logs []models.AuditLog
	err := r.DB.Where("resource_id = ?", resourceID).Order("created_at desc").Limit(limit).Offset(offset).Find(&logs).Error
	return logs, err
}

func (r *AuditRepository) LogPermissionGranted(grantedBy *uuid.UUID, granteeID uuid.UUID, fileOrFolderID uuid.UUID, permissionType string, isFolder bool, ip, userAgent string) error {
	resourceType := "file"
	if isFolder {
		resourceType = "folder"
	}

	meta := map[string]interface{}{
		"grantee_user_id":   granteeID.String(),
		"permission_type":   permissionType,
		"is_folder":         isFolder,
		"file_or_folder_id": fileOrFolderID.String(),
	}

	return r.Log(grantedBy, "permission_granted", resourceType, fileOrFolderID, ip, userAgent, meta)
}

func (r *AuditRepository) LogPermissionRevoked(revokedBy *uuid.UUID, permissionID uuid.UUID, ip, userAgent string) error {
	return r.Log(revokedBy, "permission_revoked", "permission", permissionID, ip, userAgent, nil)
}

func (r *AuditRepository) LogPermissionUpdated(updatedBy *uuid.UUID, permissionID uuid.UUID, oldPermissionType, newPermissionType string, ip, userAgent string) error {
	meta := map[string]interface{}{
		"old_permission_type": oldPermissionType,
		"new_permission_type": newPermissionType,
	}

	return r.Log(updatedBy, "permission_updated", "permission", permissionID, ip, userAgent, meta)
}

func (r *AuditRepository) LogRoleAssigned(assignedBy *uuid.UUID, userID uuid.UUID, role string, organizationID uuid.UUID, ip, userAgent string) error {
	meta := map[string]interface{}{
		"user_id":         userID.String(),
		"role":            role,
		"organization_id": organizationID.String(),
	}

	return r.Log(assignedBy, "role_assigned", "organization", organizationID, ip, userAgent, meta)
}
