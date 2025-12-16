package repositories

import (
	"citadel-drive/internal/models"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
)

const (
	// PermissionCacheTTL is the time-to-live for cached permissions (5 minutes)
	PermissionCacheTTL = 5 * time.Minute
)

type PermissionCache struct {
	mu    sync.RWMutex
	cache map[string]*cachedPermission
}

type cachedPermission struct {
	perm      *models.Permission
	expiresAt time.Time
}

// NewPermissionCache creates a new permission cache
func NewPermissionCache() *PermissionCache {
	return &PermissionCache{
		cache: make(map[string]*cachedPermission),
	}
}

// Get retrieves a cached permission if it exists and hasn't expired
func (pc *PermissionCache) Get(userID, fileID uuid.UUID) (*models.Permission, bool) {
	pc.mu.RLock()
	defer pc.mu.RUnlock()

	key := fmt.Sprintf("file:%s:user:%s", fileID.String(), userID.String())
	if cached, ok := pc.cache[key]; ok && time.Now().Before(cached.expiresAt) {
		return cached.perm, true
	}

	return nil, false
}

// GetFolder retrieves a cached folder permission if it exists and hasn't expired
func (pc *PermissionCache) GetFolder(userID, folderID uuid.UUID) (*models.Permission, bool) {
	pc.mu.RLock()
	defer pc.mu.RUnlock()

	key := fmt.Sprintf("folder:%s:user:%s", folderID.String(), userID.String())
	if cached, ok := pc.cache[key]; ok && time.Now().Before(cached.expiresAt) {
		return cached.perm, true
	}

	return nil, false
}

// Set caches a permission with TTL
func (pc *PermissionCache) Set(userID, fileID uuid.UUID, perm *models.Permission) {
	pc.mu.Lock()
	defer pc.mu.Unlock()

	key := fmt.Sprintf("file:%s:user:%s", fileID.String(), userID.String())
	pc.cache[key] = &cachedPermission{
		perm:      perm,
		expiresAt: time.Now().Add(PermissionCacheTTL),
	}
}

// SetFolder caches a folder permission with TTL
func (pc *PermissionCache) SetFolder(userID, folderID uuid.UUID, perm *models.Permission) {
	pc.mu.Lock()
	defer pc.mu.Unlock()

	key := fmt.Sprintf("folder:%s:user:%s", folderID.String(), userID.String())
	pc.cache[key] = &cachedPermission{
		perm:      perm,
		expiresAt: time.Now().Add(PermissionCacheTTL),
	}
}

// SetNegative caches a "no permission" result
func (pc *PermissionCache) SetNegative(userID, fileID uuid.UUID) {
	pc.mu.Lock()
	defer pc.mu.Unlock()

	key := fmt.Sprintf("file:%s:user:%s", fileID.String(), userID.String())
	pc.cache[key] = &cachedPermission{
		perm:      nil,
		expiresAt: time.Now().Add(PermissionCacheTTL),
	}
}

// SetFolderNegative caches a "no permission" result for a folder
func (pc *PermissionCache) SetFolderNegative(userID, folderID uuid.UUID) {
	pc.mu.Lock()
	defer pc.mu.Unlock()

	key := fmt.Sprintf("folder:%s:user:%s", folderID.String(), userID.String())
	pc.cache[key] = &cachedPermission{
		perm:      nil,
		expiresAt: time.Now().Add(PermissionCacheTTL),
	}
}

// InvalidateUser invalidates all cache entries for a specific user
func (pc *PermissionCache) InvalidateUser(userID uuid.UUID) {
	pc.mu.Lock()
	defer pc.mu.Unlock()

	userStr := userID.String()
	for key := range pc.cache {
		if fmt.Sprintf("user:%s", userStr) == key[len(key)-len(userStr)-5:] {
			delete(pc.cache, key)
		}
	}
}

// InvalidateFile invalidates all cache entries for a specific file
func (pc *PermissionCache) InvalidateFile(fileID uuid.UUID) {
	pc.mu.Lock()
	defer pc.mu.Unlock()

	fileStr := fileID.String()
	for key := range pc.cache {
		if fmt.Sprintf("file:%s", fileStr) == key[:len("file:")+len(fileStr)] {
			delete(pc.cache, key)
		}
	}
}

// InvalidateFolder invalidates all cache entries for a specific folder
func (pc *PermissionCache) InvalidateFolder(folderID uuid.UUID) {
	pc.mu.Lock()
	defer pc.mu.Unlock()

	folderStr := folderID.String()
	for key := range pc.cache {
		if fmt.Sprintf("folder:%s", folderStr) == key[:len("folder:")+len(folderStr)] {
			delete(pc.cache, key)
		}
	}
}

// Clear clears all cached permissions
func (pc *PermissionCache) Clear() {
	pc.mu.Lock()
	defer pc.mu.Unlock()

	pc.cache = make(map[string]*cachedPermission)
}
