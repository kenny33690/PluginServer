package plugin

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

type Registry struct {
	db *gorm.DB
}

type pluginRecord struct {
	ID         uint      `gorm:"column:id;primaryKey;autoIncrement"`
	Name       string    `gorm:"column:name;not null;uniqueIndex"`
	CertString string    `gorm:"column:cert_string;not null"`
	Subject    string    `gorm:"column:subject;not null"`
	NotBefore  time.Time `gorm:"column:not_before;not null"`
	NotAfter   time.Time `gorm:"column:not_after;not null"`
	CreatedAt  time.Time `gorm:"column:created_at;not null;autoCreateTime"`
}

func (pluginRecord) TableName() string {
	return "PluginRegistry"
}

type pluginVersion struct {
	ID        uint      `gorm:"column:id;primaryKey;autoIncrement"`
	Name      string    `gorm:"column:name;not null;index"`
	Version   string    `gorm:"column:version;not null"`
	IsEnabled bool      `gorm:"column:is_enabled;default:true"`
	Binary    []byte    `gorm:"column:binary"`
	Checksum  string    `gorm:"column:checksum"`
	Sign      []byte    `gorm:"column:sign"`
	CreatedAt time.Time `gorm:"column:created_at;not null;autoCreateTime"`
	UpdatedAt time.Time `gorm:"column:updated_at;not null;autoUpdateTime"`
}

func (pluginVersion) TableName() string {
	return "PluginVersions"
}

func OpenRegistry(ctx context.Context, dsn string) (*Registry, error) {
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}

	registry := &Registry{db: db}
	if err := registry.init(ctx); err != nil {
		return nil, err
	}

	return registry, nil
}

func (r *Registry) Close() error {
	if r == nil || r.db == nil {
		return nil
	}

	sqlDB, err := r.db.DB()
	if err != nil {
		return fmt.Errorf("get sql db: %w", err)
	}
	return sqlDB.Close()
}

func (r *Registry) init(ctx context.Context) error {
	if err := r.db.WithContext(ctx).AutoMigrate(&pluginRecord{}, &pluginVersion{}); err != nil {
		return fmt.Errorf("migrate tables: %w", err)
	}

	return nil
}

func (r *Registry) SavePlugin(ctx context.Context, name string, certString string, subject string, notBefore time.Time, notAfter time.Time) error {
	record := pluginRecord{
		Name:       name,
		CertString: certString,
		Subject:    subject,
		NotBefore:  notBefore.UTC(),
		NotAfter:   notAfter.UTC(),
	}

	if err := r.db.WithContext(ctx).Create(&record).Error; err != nil {
		return fmt.Errorf("insert PluginRegistry: %w", err)
	}

	return nil
}

func (r *Registry) GetPlugin(ctx context.Context, name string) (*PluginInfo, error) {
	var record pluginRecord

	err := r.db.WithContext(ctx).Where("name = ?", name).Take(&record).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, nil
		}
		return nil, fmt.Errorf("query PluginRegistry: %w", err)
	}

	return &PluginInfo{
		Name: record.Name,
		Cert: record.CertString,
	}, nil
}

func (r *Registry) UpdatePluginBinary(ctx context.Context, name string, version string, binary []byte, checksum string, sign []byte) error {
	versionRecord := pluginVersion{
		Name:      name,
		Version:   version,
		Binary:    binary,
		Checksum:  checksum,
		Sign:      sign,
		IsEnabled: true,
	}

	if err := r.db.WithContext(ctx).Create(&versionRecord).Error; err != nil {
		return fmt.Errorf("insert PluginVersions: %w", err)
	}
	return nil
}
