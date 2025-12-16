package repositories

import (
	"citadel-drive/internal/models"
	"errors"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

const (
	RoleOwner = "Owner"
	RoleEditor = "Editor"
	RoleViewer = "Viewer"
	RoleGuest = "Guest"
	RoleAdmin = "Admin"
)

var AllRoles = []string{
	RoleOwner,
	RoleEditor,
	RoleViewer,
	RoleGuest,
	RoleAdmin,
}

var RolePermissions = map[string][]string{
	RoleAdmin:  {PermissionRead, PermissionWrite, PermissionUpdate, PermissionDelete, PermissionAdmin},
	RoleOwner:  {PermissionRead, PermissionWrite, PermissionUpdate, PermissionDelete, PermissionAdmin},
	RoleEditor: {PermissionRead, PermissionWrite, PermissionUpdate},
	RoleViewer: {PermissionRead},
	RoleGuest:  {},
}

type RoleRepository struct {
	db *gorm.DB
}

func NewRoleRepository(db *gorm.DB) *RoleRepository {
	return &RoleRepository{db: db}
}

// AssignRole assigns a role to a user in an organization
func (r *RoleRepository) AssignRole(userID, organizationID uuid.UUID, role string) (*models.UserPermission, error) {
	if !isValidRole(role) {
		return nil, errors.New("invalid role")
	}

	userPerm := &models.UserPermission{
		ID:             uuid.New(),
		UserID:         userID,
		OrganizationID: organizationID,
		Role:           role,
		CreatedAt:      time.Now(),
	}

	// Use upsert logic: try to update existing, or create if not found
	result := r.db.Where("user_id = ? AND organization_id = ?", userID, organizationID).
		Assign(userPerm).
		FirstOrCreate(userPerm)

	if result.Error != nil {
		return nil, result.Error
	}

	return userPerm, nil
}

// GetUserRole gets a user's role in an organization
func (r *RoleRepository) GetUserRole(userID, organizationID uuid.UUID) (*models.UserPermission, error) {
	var userPerm models.UserPermission
	err := r.db.Where("user_id = ? AND organization_id = ?", userID, organizationID).First(&userPerm).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return &userPerm, nil
}

// GetOrganizationUsers gets all users in an organization with their roles
func (r *RoleRepository) GetOrganizationUsers(organizationID uuid.UUID) ([]models.UserPermission, error) {
	var userPerms []models.UserPermission
	err := r.db.Where("organization_id = ?", organizationID).Find(&userPerms).Error
	return userPerms, err
}

// RemoveUserRole removes a user's role in an organization
func (r *RoleRepository) RemoveUserRole(userID, organizationID uuid.UUID) error {
	return r.db.Where("user_id = ? AND organization_id = ?", userID, organizationID).
		Delete(&models.UserPermission{}).Error
}

// GetAvailableRoles returns the list of all available roles
func (r *RoleRepository) GetAvailableRoles() []string {
	return AllRoles
}

// GetRolePermissions returns the permissions associated with a role
func (r *RoleRepository) GetRolePermissions(role string) ([]string, error) {
	if !isValidRole(role) {
		return nil, errors.New("invalid role")
	}
	return RolePermissions[role], nil
}

// CanUserManagePermissions checks if a user can manage permissions (is admin/owner)
func (r *RoleRepository) CanUserManagePermissions(userID, organizationID uuid.UUID) (bool, error) {
	userPerm, err := r.GetUserRole(userID, organizationID)
	if err != nil {
		return false, err
	}

	if userPerm == nil {
		return false, nil
	}

	return userPerm.Role == RoleAdmin || userPerm.Role == RoleOwner, nil
}

// Helper function
func isValidRole(role string) bool {
	for _, r := range AllRoles {
		if r == role {
			return true
		}
	}
	return false
}
