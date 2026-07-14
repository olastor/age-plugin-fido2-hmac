package plugin

import (
	"sync"
	"testing"
)

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
