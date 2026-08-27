// Package notifiers send human-readable summaries to communication
// channels (PR comments, Slack, stdout).
//
// Notifiers are intentionally separate from publishers: a publisher
// stores machine-readable data; a notifier interrupts a human.
package notifiers
