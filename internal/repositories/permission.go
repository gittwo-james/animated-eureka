package repositories

import (
	"citadel-drive/internal/models"
	"errors"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

const (
	PermissionRead   = "read"
	PermissionWrite  = "write"
	PermissionUpdate = "update"
	PermissionDelete = "delete"
	PermissionAdmin  = "admin"
)

var AllPermissions = []string{
	PermissionRead,
	PermissionWrite,
	PermissionUpdate,
	PermissionDelete,
	PermissionAdmin,
}

var PermissionHierarchy = map[string]int{
	PermissionRead:   1,
	PermissionWrite:  2,
	PermissionUpdate: 3,
	PermissionDelete: 4,
	PermissionAdmin:  5,
}

type PermissionRepository struct {
	db *gorm.DB
}

func NewPermissionRepository(db *gorm.DB) *PermissionRepository {
	return &PermissionRepository{db: db}
}

// GrantPermission grants a permission to a user for a file or folder
func (r *PermissionRepository) GrantPermission(userID, fileOrFolderID uuid.UUID, isFolder bool, permissionType string, grantedBy uuid.UUID, expiresAt *time.Time) (*models.Permission, error) {
	if !isValidPermissionType(permissionType) {
		return nil, errors.New("invalid permission type")
	}

	perm := &models.Permission{
		ID:             uuid.New(),
		UserID:         userID,
		PermissionType: permissionType,
		GrantedBy:      &grantedBy,
		ExpiresAt:      expiresAt,
	}

	if isFolder {
		perm.FolderID = &fileOrFolderID
	} else {
		perm.FileID = &fileOrFolderID
	}

	if err := r.db.Create(perm).Error; err != nil {
		return nil, err
	}

	return perm, nil
}

// RevokePermission removes a permission
func (r *PermissionRepository) RevokePermission(permissionID uuid.UUID) error {
	return r.db.Delete(&models.Permission{}, "id = ?", permissionID).Error
}

// GetUserPermissionForFile gets the permission a user has for a specific file
func (r *PermissionRepository) GetUserPermissionForFile(userID, fileID uuid.UUID) (*models.Permission, error) {
	var perm models.Permission
	err := r.db.Where("user_id = ? AND file_id = ? AND (expires_at IS NULL OR expires_at > ?)", userID, fileID, time.Now()).First(&perm).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &perm, nil
}

// GetUserPermissionForFolder gets the permission a user has for a specific folder
func (r *PermissionRepository) GetUserPermissionForFolder(userID, folderID uuid.UUID) (*models.Permission, error) {
	var perm models.Permission
	err := r.db.Where("user_id = ? AND folder_id = ? AND (expires_at IS NULL OR expires_at > ?)", userID, folderID, time.Now()).First(&perm).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &perm, nil
}

// GetFilePermissions gets all permissions for a file
func (r *PermissionRepository) GetFilePermissions(fileID uuid.UUID) ([]models.Permission, error) {
	var perms []models.Permission
	err := r.db.Where("file_id = ? AND (expires_at IS NULL OR expires_at > ?)", fileID, time.Now()).Find(&perms).Error
	return perms, err
}

// GetFolderPermissions gets all permissions for a folder
func (r *PermissionRepository) GetFolderPermissions(folderID uuid.UUID) ([]models.Permission, error) {
	var perms []models.Permission
	err := r.db.Where("folder_id = ? AND (expires_at IS NULL OR expires_at > ?)", folderID, time.Now()).Find(&perms).Error
	return perms, err
}

// GetUserPermissions gets all permissions for a user
func (r *PermissionRepository) GetUserPermissions(userID uuid.UUID) ([]models.Permission, error) {
	var perms []models.Permission
	err := r.db.Where("user_id = ? AND (expires_at IS NULL OR expires_at > ?)", userID, time.Now()).Find(&perms).Error
	return perms, err
}

// UpdatePermission updates a permission type or expiration
func (r *PermissionRepository) UpdatePermission(permissionID uuid.UUID, permissionType *string, expiresAt *time.Time) error {
	updates := map[string]interface{}{}
	if permissionType != nil && isValidPermissionType(*permissionType) {
		updates["permission_type"] = *permissionType
	}
	if expiresAt != nil {
		updates["expires_at"] = expiresAt
	}

	if len(updates) == 0 {
		return errors.New("no valid updates provided")
	}

	return r.db.Model(&models.Permission{}).Where("id = ?", permissionID).Updates(updates).Error
}

// InvalidateExpiredPermissions marks expired permissions for cleanup
func (r *PermissionRepository) InvalidateExpiredPermissions() error {
	return r.db.Where("expires_at IS NOT NULL AND expires_at <= ?", time.Now()).Delete(&models.Permission{}).Error
}

// CheckUserCanAccessFile checks if a user can access a file
func (r *PermissionRepository) CheckUserCanAccessFile(userID, fileID uuid.UUID, requiredPermission string) (bool, error) {
	file := &models.File{}
	if err := r.db.First(file, "id = ?", fileID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return false, nil
		}
		return false, err
	}

	// Owner has all permissions
	if file.OwnerID == userID {
		return true, nil
	}

	// Check direct file permission
	perm, err := r.GetUserPermissionForFile(userID, fileID)
	if err != nil {
		return false, err
	}

	if perm != nil && canSatisfyPermission(perm.PermissionType, requiredPermission) {
		return true, nil
	}

	// Check folder permission (inheritance)
	if file.FolderID != nil {
		return r.CheckUserCanAccessFolder(userID, *file.FolderID, requiredPermission)
	}

	return false, nil
}

// CheckUserCanAccessFolder checks if a user can access a folder and inherited permissions
func (r *PermissionRepository) CheckUserCanAccessFolder(userID, folderID uuid.UUID, requiredPermission string) (bool, error) {
	folder := &models.Folder{}
	if err := r.db.First(folder, "id = ?", folderID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return false, nil
		}
		return false, err
	}

	// Owner has all permissions
	if folder.OwnerID == userID {
		return true, nil
	}

	// Check direct folder permission
	perm, err := r.GetUserPermissionForFolder(userID, folderID)
	if err != nil {
		return false, err
	}

	if perm != nil && canSatisfyPermission(perm.PermissionType, requiredPermission) {
		return true, nil
	}

	// Check parent folder permissions (recursive)
	if folder.ParentID != nil {
		return r.CheckUserCanAccessFolder(userID, *folder.ParentID, requiredPermission)
	}

	return false, nil
}

// Helper functions
func isValidPermissionType(permType string) bool {
	for _, p := range AllPermissions {
		if p == permType {
			return true
		}
	}
	return false
}

// canSatisfyPermission checks if a permission level satisfies the required permission
// For example, admin permission satisfies all requirements
func canSatisfyPermission(grantedPermission, requiredPermission string) bool {
	grantedLevel, ok1 := PermissionHierarchy[grantedPermission]
	requiredLevel, ok2 := PermissionHierarchy[requiredPermission]

	if !ok1 || !ok2 {
		return false
	}

	return grantedLevel >= requiredLevel
}
