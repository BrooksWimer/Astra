package strategy

import (
	"sync"

	"github.com/netwise/agent/internal/config"
)

var (
	runtimeConfigMu sync.RWMutex
	runtimeConfig   *config.Config
)

func SetRuntimeConfig(cfg *config.Config) {
	runtimeConfigMu.Lock()
	defer runtimeConfigMu.Unlock()
	if cfg == nil {
		runtimeConfig = nil
		return
	}
	cloned := *cfg
	runtimeConfig = &cloned
}

func CurrentConfig() *config.Config {
	runtimeConfigMu.RLock()
	defer runtimeConfigMu.RUnlock()
	if runtimeConfig == nil {
		return nil
	}
	cloned := *runtimeConfig
	return &cloned
}
