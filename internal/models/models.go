package models

import (
    "time"

    "github.com/google/uuid"
    "gorm.io/datatypes"
    "gorm.io/gorm"
)

type Organization struct {
    ID        uuid.UUID `gorm:"type:uuid;default:gen_random_uuid();primaryKey"`
    Name      string    `gorm:"not null;index"`
    CreatedAt time.Time `gorm:"not null;autoCreateTime;index"`
    UpdatedAt time.Time `gorm:"not null;autoUpdateTime"`

    Users []User `gorm:"constraint:OnUpdate:CASCADE,OnDelete:RESTRICT;"`
    Files []File `gorm:"constraint:OnUpdate:CASCADE,OnDelete:RESTRICT;"`
}

type User struct {
    ID             uuid.UUID `gorm:"type:uuid;default:gen_random_uuid();primaryKey"`
    Email          string    `gorm:"not null;uniqueIndex"`
    PasswordHash   string    `gorm:"not null"`
    FullName       string    `gorm:"not null"`
    OrganizationID uuid.UUID `gorm:"type:uuid;not null;index"`

    TotpSecret      *string    `gorm:"type:text"`
    TotpEnabled     bool       `gorm:"not null;default:false;index"`
    TotpConfirmedAt *time.Time `gorm:"index"`

    PasswordResetTokenHash *string    `gorm:"type:text;index"`
    PasswordResetExpiresAt *time.Time `gorm:"index"`

    UnlockTokenHash      *string    `gorm:"type:text;index"`
    UnlockTokenExpiresAt *time.Time `gorm:"index"`

    IsActive            bool       `gorm:"not null;default:true;index"`
    FailedLoginAttempts int        `gorm:"not null;default:0"`
    LockedUntil         *time.Time `gorm:"index"`
    CreatedAt           time.Time  `gorm:"not null;autoCreateTime;index"`
    UpdatedAt           time.Time  `gorm:"not null;autoUpdateTime"`

    Organization Organization    `gorm:"foreignKey:OrganizationID"`
    Sessions     []Session       `gorm:"constraint:OnUpdate:CASCADE,OnDelete:CASCADE;"`
    BackupCodes  []UserBackupCode `gorm:"constraint:OnUpdate:CASCADE,OnDelete:CASCADE;"`
}

type Folder struct {
    ID             uuid.UUID      `gorm:"type:uuid;default:gen_random_uuid();primaryKey"`
    Name           string         `gorm:"not null;index"`
    ParentID       *uuid.UUID     `gorm:"type:uuid;index"`
    OrganizationID uuid.UUID      `gorm:"type:uuid;not null;index"`
    CreatedAt      time.Time      `gorm:"not null;autoCreateTime;index"`
    UpdatedAt      time.Time      `gorm:"not null;autoUpdateTime"`
    DeletedAt      gorm.DeletedAt `gorm:"index"`

    Organization Organization `gorm:"foreignKey:OrganizationID"`
    Parent       *Folder      `gorm:"foreignKey:ParentID"`
    Children     []Folder     `gorm:"foreignKey:ParentID"`
    Files        []File       `gorm:"foreignKey:FolderID"`
}

type File struct {
    ID              uuid.UUID      `gorm:"type:uuid;default:gen_random_uuid();primaryKey"`
    OwnerID         uuid.UUID      `gorm:"type:uuid;not null;index"`
    OrganizationID  uuid.UUID      `gorm:"type:uuid;not null;index"`
    FolderID        *uuid.UUID     `gorm:"type:uuid;index"`
    Name            string         `gorm:"not null;index"`
    Description     string         `gorm:"type:text"`
    FileType        string         `gorm:"not null;index"`
    Size            int64          `gorm:"not null"`
    StoragePathR2   string         `gorm:"not null"`
    EncryptionKeyID *uuid.UUID     `gorm:"type:uuid;index"`
    CreatedAt       time.Time      `gorm:"not null;autoCreateTime;index"`
    UpdatedAt       time.Time      `gorm:"not null;autoUpdateTime"`
    DeletedAt       gorm.DeletedAt `gorm:"index"`

    Owner        User          `gorm:"foreignKey:OwnerID"`
    Organization Organization  `gorm:"foreignKey:OrganizationID"`
    Versions     []FileVersion `gorm:"constraint:OnUpdate:CASCADE,OnDelete:CASCADE;"`
    Permissions  []Permission  `gorm:"constraint:OnUpdate:CASCADE,OnDelete:CASCADE;"`
    Tags         []FileTag     `gorm:"constraint:OnUpdate:CASCADE,OnDelete:CASCADE;"`
    SharedTokens []SharedToken `gorm:"constraint:OnUpdate:CASCADE,OnDelete:CASCADE;"`

    CurrentEncryptionKey *EncryptionKey  `gorm:"foreignKey:EncryptionKeyID;references:ID"`
    EncryptionKeys       []EncryptionKey `gorm:"constraint:OnUpdate:CASCADE,OnDelete:CASCADE;"`
}

type FileVersion struct {
    ID            uuid.UUID `gorm:"type:uuid;default:gen_random_uuid();primaryKey"`
    FileID        uuid.UUID `gorm:"type:uuid;not null;index"`
    VersionNumber int       `gorm:"not null"`
    StoragePathR2 string    `gorm:"not null"`
    FileSize      int64     `gorm:"not null"`
    Sha256Hash    string    `gorm:"not null"`
    Md5Hash       string    `gorm:"not null"`
    CreatedBy     uuid.UUID `gorm:"type:uuid;not null;index"`
    CreatedAt     time.Time `gorm:"not null;autoCreateTime;index"`

    File File `gorm:"foreignKey:FileID"`
}

type Permission struct {
    ID             uuid.UUID  `gorm:"type:uuid;default:gen_random_uuid();primaryKey"`
    UserID         uuid.UUID  `gorm:"type:uuid;not null;index"`
    FileID         *uuid.UUID `gorm:"type:uuid;index"`
    FolderID       *uuid.UUID `gorm:"type:uuid;index"`
    PermissionType string     `gorm:"not null;index"`
    ExpiresAt      *time.Time `gorm:"index"`
    CreatedAt      time.Time  `gorm:"not null;autoCreateTime;index"`

    User User  `gorm:"foreignKey:UserID"`
    File *File `gorm:"foreignKey:FileID"`
}

type UserPermission struct {
    ID             uuid.UUID `gorm:"type:uuid;default:gen_random_uuid();primaryKey"`
    UserID         uuid.UUID `gorm:"type:uuid;not null;index:idx_user_permissions_user_org,unique;index"`
    OrganizationID uuid.UUID `gorm:"type:uuid;not null;index:idx_user_permissions_user_org,unique;index"`
    Role           string    `gorm:"not null;index"`
    CreatedAt      time.Time `gorm:"not null;autoCreateTime;index"`

    User         User         `gorm:"foreignKey:UserID"`
    Organization Organization `gorm:"foreignKey:OrganizationID"`
}

type AuditLog struct {
    ID           uuid.UUID      `gorm:"type:uuid;default:gen_random_uuid();primaryKey"`
    UserID       *uuid.UUID     `gorm:"type:uuid;index"`
    Action       string         `gorm:"not null;index"`
    ResourceType string         `gorm:"not null;index"`
    ResourceID   uuid.UUID      `gorm:"type:uuid;not null;index"`
    IPAddress    string         `gorm:"not null;index"`
    UserAgent    string         `gorm:"type:text"`
    Metadata     datatypes.JSON `gorm:"type:jsonb"`
    CreatedAt    time.Time      `gorm:"not null;autoCreateTime;index"`

    User *User `gorm:"foreignKey:UserID"`
}

type Session struct {
    ID        uuid.UUID `gorm:"type:uuid;default:gen_random_uuid();primaryKey"`
    UserID    uuid.UUID `gorm:"type:uuid;not null;index"`
    TokenHash string    `gorm:"not null;index"`
    IPAddress string    `gorm:"not null;index"`
    UserAgent string    `gorm:"type:text"`
    ExpiresAt time.Time `gorm:"not null;index"`
    IsActive  bool      `gorm:"not null;default:true;index"`
    CreatedAt time.Time `gorm:"not null;autoCreateTime;index"`

    User User `gorm:"foreignKey:UserID"`
}

type TokenBlacklist struct {
    ID        uuid.UUID `gorm:"type:uuid;default:gen_random_uuid();primaryKey"`
    TokenHash string    `gorm:"not null;uniqueIndex"`
    ExpiresAt time.Time `gorm:"not null;index"`
    CreatedAt time.Time `gorm:"not null;autoCreateTime;index"`
}

type UserBackupCode struct {
    ID        uuid.UUID  `gorm:"type:uuid;default:gen_random_uuid();primaryKey"`
    UserID    uuid.UUID  `gorm:"type:uuid;not null;index"`
    CodeHash  string     `gorm:"not null;index"`
    UsedAt    *time.Time `gorm:"index"`
    CreatedAt time.Time  `gorm:"not null;autoCreateTime;index"`

    User User `gorm:"foreignKey:UserID"`
}

type EncryptionKey struct {
    ID          uuid.UUID `gorm:"type:uuid;default:gen_random_uuid();primaryKey"`
    FileID      uuid.UUID `gorm:"type:uuid;not null;index"`
    KeyMaterial []byte    `gorm:"type:bytea;not null"`
    Algorithm   string    `gorm:"not null;index"`
    CreatedAt   time.Time `gorm:"not null;autoCreateTime;index"`

    File File `gorm:"foreignKey:FileID"`
}

type SharedToken struct {
    ID            uuid.UUID  `gorm:"type:uuid;default:gen_random_uuid();primaryKey"`
    FileID        uuid.UUID  `gorm:"type:uuid;not null;index"`
    CreatedBy     uuid.UUID  `gorm:"type:uuid;not null;index"`
    TokenHash     string     `gorm:"not null;uniqueIndex"`
    ExpiresAt     *time.Time `gorm:"index"`
    MaxDownloads  int        `gorm:"not null;default:0"`
    DownloadCount int        `gorm:"not null;default:0"`
    CreatedAt     time.Time  `gorm:"not null;autoCreateTime;index"`

    File File `gorm:"foreignKey:FileID"`
}

type FileTag struct {
    ID        uuid.UUID `gorm:"type:uuid;default:gen_random_uuid();primaryKey"`
    FileID    uuid.UUID `gorm:"type:uuid;not null;index:idx_file_tags_file_tag,unique"`
    TagName   string    `gorm:"not null;index:idx_file_tags_file_tag,unique"`
    CreatedAt time.Time `gorm:"not null;autoCreateTime;index"`

    File File `gorm:"foreignKey:FileID"`
}

type IPBlacklist struct {
    ID        uuid.UUID `gorm:"type:uuid;default:gen_random_uuid();primaryKey"`
    IPAddress string    `gorm:"not null;uniqueIndex"`
    Reason    string    `gorm:"type:text"`
    CreatedAt time.Time `gorm:"not null;autoCreateTime;index"`
}
