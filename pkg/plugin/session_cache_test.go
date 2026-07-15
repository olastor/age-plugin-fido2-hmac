package plugin

import (
	"bytes"
	"sync"
	"testing"
)

func TestSessionCacheGetReturnsLoadedSecret(t *testing.T) {
	cache := NewSessionCache()
	defer cache.Close()

	want := []byte("command-scoped secret")
	if _, err := cache.Load("identity", func() ([]byte, error) { return want, nil }); err != nil {
		t.Fatalf("Load: %v", err)
	}

	got, ok := cache.Get("identity")
	if !ok {
		t.Fatal("Get missed a loaded identity")
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("Get returned %q, want %q", got, want)
	}
}

func TestSessionCacheCloseWakesConcurrentLoaders(t *testing.T) {
	cache := NewSessionCache()
	started := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once

	load := func() ([]byte, error) {
		once.Do(func() { close(started) })
		<-release
		return []byte("derived-secret"), nil
	}

	results := make(chan error, 2)
	go func() {
		_, err := cache.Load("identity", load)
		results <- err
	}()
	<-started
	go func() {
		_, err := cache.Load("identity", load)
		results <- err
	}()

	cache.Close()
	close(release)
	for range 2 {
		if err := <-results; err == nil {
			t.Fatal("loader succeeded after session cache was closed")
		}
	}
}
