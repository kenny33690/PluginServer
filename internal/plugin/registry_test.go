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

func TestGetPlugin(t *testing.T) {
	ctx := context.Background()
	registry, err := OpenRegistry(ctx, "file:registry-test-get?mode=memory&cache=shared")
	if err != nil {
		t.Fatalf("open registry: %v", err)
	}
	defer registry.Close()

	now := time.Now()
	name := "demo"
	cert := "cert-1"
	if err := registry.SavePlugin(ctx, name, cert, "subject-1", now, now.Add(time.Hour)); err != nil {
		t.Fatalf("save plugin: %v", err)
	}

	info, err := registry.GetPlugin(ctx, name)
	if err != nil {
		t.Fatalf("get plugin: %v", err)
	}
	if info == nil {
		t.Fatal("expected plugin to be found")
	}
	if info.Name != name {
		t.Fatalf("expected name %s, got %s", name, info.Name)
	}
	if info.Cert != cert {
		t.Fatalf("expected cert %s, got %s", cert, info.Cert)
	}
}
