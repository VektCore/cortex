package scanners

import (
	"sync"

	"github.com/samber/mo"

	"github.com/vektcore/cortex/internal/application/ports"
	"github.com/vektcore/cortex/internal/domain/finding"
	"github.com/vektcore/cortex/internal/domain/shared"
)

// Registry is the default in-memory ScannerRegistry.
// All methods are safe for concurrent use.
type Registry struct {
	mu       sync.RWMutex
	scanners map[finding.ScannerName]ports.Scanner
}

// New returns an empty Registry. Scanners can be registered immediately.
func New() *Registry {
	return &Registry{
		scanners: make(map[finding.ScannerName]ports.Scanner),
	}
}

// Register adds or replaces a Scanner. It is safe to call after the registry
// is already in use.
func (r *Registry) Register(s ports.Scanner) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.scanners[s.Name()] = s
}

// Get returns the Scanner with the given name, if one is registered.
func (r *Registry) Get(name finding.ScannerName) mo.Option[ports.Scanner] {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if s, ok := r.scanners[name]; ok {
		return shared.Some(s)
	}
	return shared.None[ports.Scanner]()
}

// All returns every registered Scanner in non-deterministic order.
func (r *Registry) All() []ports.Scanner {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]ports.Scanner, 0, len(r.scanners))
	for _, s := range r.scanners {
		out = append(out, s)
	}
	return out
}

// ForLanguage returns Scanners that declare support for lang.
func (r *Registry) ForLanguage(lang shared.Language) []ports.Scanner {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []ports.Scanner
	for _, s := range r.scanners {
		for _, l := range s.SupportedLanguages() {
			if l == lang {
				out = append(out, s)
				break
			}
		}
	}
	return out
}

// ForLanguages returns deduplicated Scanners that support any of langs.
func (r *Registry) ForLanguages(langs []shared.Language) []ports.Scanner {
	seen := make(map[finding.ScannerName]struct{})
	var out []ports.Scanner
	for _, lang := range langs {
		for _, s := range r.ForLanguage(lang) {
			if _, dup := seen[s.Name()]; !dup {
				seen[s.Name()] = struct{}{}
				out = append(out, s)
			}
		}
	}
	return out
}
