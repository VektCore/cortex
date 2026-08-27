// Package config loads .cortex.yaml and exposes it as a typed struct.
//
// Backed by viper: supports YAML, environment-variable interpolation
// (${VAR}), and overrides from CLI flags. Validation happens here, before
// the value is handed to the application layer.
package config
