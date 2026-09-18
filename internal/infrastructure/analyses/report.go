package analyses

import "time"

// Report is one analysis as it is stored: the same record a client polls, and
// nothing more.
//
// The fields and their JSON tags mirror the HTTP layer's Analysis one for one.
// They are redeclared rather than imported because infrastructure must not
// depend on interfaces, and because these names are a public contract: a
// client reads them out of the poll response, so renaming a tag here breaks
// callers even though nothing in this package would fail to compile.
//
// Findings themselves are not here. Their triage lifecycle is owned by
// VektCore_Platform's sast_findings; a per-finding table on this side would
// be a second source of truth for a decision only one system is allowed to
// make. What survives the run is the counts and the SARIF document.
type Report struct {
	ID string `json:"id"`
	// Owner is the client the record belongs to. It is what scopes every read
	// of this table to one tenant, and it is separate from RequestedBy on
	// purpose: RequestedBy is audit text that may say anything, while this is
	// an access-control decision.
	//
	// An empty owner is a row written before ownership existed. It is nobody's
	// and is served to nobody but an operator.
	Owner string `json:"owner,omitempty"`
	// Project is the owner-scoped key ("<owner>/<name>"), because project
	// names are caller-chosen and a global namespace let two clients share —
	// and overwrite — one finding history.
	Project string `json:"project"`
	// Source decides what the rest of the row can be trusted to say: an
	// uploaded archive carries no git metadata of its own, so Repository, Ref
	// and Commit may legitimately be empty on one and not on the other.
	Source     string `json:"source"`
	Repository string `json:"repository,omitempty"`
	Ref        string `json:"ref,omitempty"`
	// Commit is the revision actually analysed, which is what a forge needs to
	// attach alerts and a status to the right place.
	Commit     string         `json:"commit,omitempty"`
	Status     string         `json:"status"`
	Gate       string         `json:"gate,omitempty"` // passed | failed
	Findings   int            `json:"findings"`
	BySeverity map[string]int `json:"by_severity,omitempty"`
	// NewFindings is how many the project had never seen, which is the number a
	// returning client actually reads. It is only meaningful against the
	// project state this store also holds.
	NewFindings int `json:"new_findings"`
	Reopened    int `json:"reopened"`
	Resolved    int `json:"resolved"`
	// ScannersRan and ScannerErrors together say how much of the scan actually
	// happened. A run where four of five tools failed must not read as clean,
	// so both are persisted even when the analysis completed.
	ScannersRan   int               `json:"scanners_ran"`
	ScannerErrors map[string]string `json:"scanner_errors,omitempty"`
	// KnownBefore is how many vulnerabilities the project already carried.
	KnownBefore int        `json:"known_before"`
	RequestedBy string     `json:"requested_by,omitempty"`
	Error       string     `json:"error,omitempty"`
	QueuedAt    time.Time  `json:"queued_at"`
	StartedAt   *time.Time `json:"started_at,omitempty"`
	FinishedAt  *time.Time `json:"finished_at,omitempty"`
}
