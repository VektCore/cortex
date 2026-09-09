package httpapi

import (
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"strings"
	"time"
)

// uploadPath is the endpoint a client's pipeline posts its source to.
const uploadPath = "/api/v1/analyses/upload"

// maxFieldBytes caps each text field of the multipart form. They are short
// metadata — a project name, a commit — and a client that sends a megabyte in
// one is not doing so by accident.
const maxFieldBytes = 4 << 10

// multipartOverhead is the slack the whole-request ceiling allows above the
// archive limit: part headers, boundaries and the metadata fields.
const multipartOverhead = 1 << 20

// uploadForm is what the pipeline sends alongside the archive.
//
// commit and branch matter because an uploaded tree has no .git: without them
// the analysis cannot say which revision it looked at, and nothing can be
// attached back to the commit that triggered it.
type uploadForm struct {
	project    string
	commit     string
	branch     string
	repository string
	bytes      int64
}

// handleUploadAnalysis accepts a source archive and queues an analysis for it.
//
// This is the deployment where the client grants no access to its code at all:
// the pipeline packages the tree it is building, posts it, and blocks on the
// verdict. Nothing here reaches back into the client's forge.
func (s *Server) handleUploadAnalysis(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "use POST")
		return
	}
	cfg := s.cfg.Server.Upload
	if !cfg.Enabled {
		writeError(w, http.StatusForbidden,
			"archive upload is disabled; set server.upload.enabled to true")
		return
	}

	id := RandomID()
	// Bound the whole request, not just the file part: the ceiling has to hold
	// even if the client never sends a part named "archive".
	r.Body = http.MaxBytesReader(w, r.Body, cfg.MaxArchiveBytes+multipartOverhead)

	form, err := s.readUpload(r, id, cfg.MaxArchiveBytes)
	if err != nil {
		_ = s.store.RemoveArchive(id)
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	analysis := Analysis{
		ID:          id,
		Project:     sanitizeSegment(form.project),
		Source:      SourceUpload,
		Repository:  form.repository,
		Ref:         form.branch,
		Commit:      form.commit,
		Status:      StatusQueued,
		RequestedBy: r.Header.Get(clientNameHeader),
		QueuedAt:    time.Now().UTC(),
	}

	if err := s.store.SaveAnalysis(analysis); err != nil {
		_ = s.store.RemoveArchive(id)
		s.logger.Error("could not queue upload", logField("error", err.Error()))
		writeError(w, http.StatusInternalServerError, "could not queue the analysis")
		return
	}
	if !s.runner.Enqueue(id) {
		_ = s.store.RemoveArchive(id)
		analysis.Status = StatusFailed
		analysis.Error = "the queue is full"
		_ = s.store.SaveAnalysis(analysis)
		writeError(w, http.StatusServiceUnavailable, "the queue is full; retry shortly")
		return
	}

	s.logger.Info("upload queued",
		logField("id", id),
		logField("project", analysis.Project),
		logField("bytes", fmt.Sprint(form.bytes)),
		logField("client", analysis.RequestedBy))

	w.Header().Set("Location", "/api/v1/analyses/"+id)
	writeJSON(w, http.StatusAccepted, analysis)
}

// readUpload streams the multipart body: metadata into memory, the archive
// straight to disk. ParseMultipartForm would buffer the archive first, which
// is the difference between a bounded server and one client can exhaust.
func (s *Server) readUpload(r *http.Request, id string, maxArchive int64) (uploadForm, error) {
	reader, err := r.MultipartReader()
	if err != nil {
		return uploadForm{}, fmt.Errorf("body must be multipart/form-data: %w", err)
	}

	form := uploadForm{}
	seenArchive := false

	for {
		part, nextErr := reader.NextPart()
		if errors.Is(nextErr, io.EOF) {
			break
		}
		if nextErr != nil {
			return uploadForm{}, fmt.Errorf("read form: %w", nextErr)
		}

		if part.FormName() == "archive" {
			written, storeErr := s.storeArchive(part, id, maxArchive)
			_ = part.Close()
			if storeErr != nil {
				return uploadForm{}, storeErr
			}
			seenArchive, form.bytes = true, written
			continue
		}

		value, readErr := readField(part)
		_ = part.Close()
		if readErr != nil {
			return uploadForm{}, readErr
		}
		form.assign(part.FormName(), value)
	}

	return form, form.validate(seenArchive)
}

// storeArchive copies the file part to disk, refusing at the ceiling rather
// than after it: the reader is capped one byte above the limit so an oversized
// upload is detected instead of silently truncated into a corrupt archive.
func (s *Server) storeArchive(part *multipart.Part, id string, maxArchive int64) (int64, error) {
	file, err := s.store.CreateArchive(id)
	if err != nil {
		s.logger.Error("could not open archive for writing", logField("error", err.Error()))
		return 0, errors.New("could not store the archive")
	}
	defer func() { _ = file.Close() }()

	written, err := io.Copy(file, io.LimitReader(part, maxArchive+1))
	if err != nil {
		return 0, fmt.Errorf("read archive: %w", err)
	}
	if written > maxArchive {
		return 0, fmt.Errorf("archive exceeds the %d byte limit", maxArchive)
	}
	if closeErr := file.Close(); closeErr != nil {
		return 0, fmt.Errorf("store archive: %w", closeErr)
	}
	return written, nil
}

func (f *uploadForm) assign(name, value string) {
	switch name {
	case "project":
		f.project = value
	case "commit":
		f.commit = value
	case "branch":
		f.branch = value
	case "repository":
		f.repository = value
	}
}

// validate refuses anything the analysis could not honestly report on.
func (f *uploadForm) validate(seenArchive bool) error {
	if !seenArchive {
		return errors.New(`a file part named "archive" is required`)
	}
	if f.bytes == 0 {
		return errors.New("the archive is empty")
	}
	if f.project == "" {
		// Derivable from a repository URL, but there is none here. Without a
		// stable project the history resets every run and "new findings" —
		// the number the client actually reads — becomes meaningless.
		return errors.New(`"project" is required: it is the key the finding history is kept under`)
	}
	return nil
}

func readField(part *multipart.Part) (string, error) {
	raw, err := io.ReadAll(io.LimitReader(part, maxFieldBytes+1))
	if err != nil {
		return "", fmt.Errorf("read field %q: %w", part.FormName(), err)
	}
	if len(raw) > maxFieldBytes {
		return "", fmt.Errorf("field %q is too long", part.FormName())
	}
	return strings.TrimSpace(string(raw)), nil
}

// removeArchive drops an uploaded archive once it is no longer needed. It holds
// the client's source: keeping it after the analysis would turn the data
// directory into a copy of every repository the service has ever seen.
func (r *Runner) removeArchive(id string) {
	if err := r.store.RemoveArchive(id); err != nil && !os.IsNotExist(err) {
		r.logger.Warn("could not remove the uploaded archive",
			logField("id", id), logField("error", err.Error()))
	}
}
