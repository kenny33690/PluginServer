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
	if err := r.db.WithContext(ctx).AutoMigrate(&pluginRecord{}); err != nil {
		return fmt.Errorf("migrate PluginRegistry: %w", err)
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
