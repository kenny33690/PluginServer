package plugin

import (
	"context"
	"testing"
	"time"
)

func TestSavePluginRejectsDuplicateName(t *testing.T) {
	ctx := context.Background()
	registry, err := OpenRegistry(ctx, "file:registry-test?mode=memory&cache=shared")
	if err != nil {
		t.Fatalf("open registry: %v", err)
	}
	defer registry.Close()

	now := time.Now()
	if err := registry.SavePlugin(ctx, "demo", "cert-1", "subject-1", now, now.Add(time.Hour)); err != nil {
		t.Fatalf("save first plugin: %v", err)
	}

	if err := registry.SavePlugin(ctx, "demo", "cert-2", "subject-2", now, now.Add(time.Hour)); err == nil {
		t.Fatal("expected duplicate name to fail")
	}
}
