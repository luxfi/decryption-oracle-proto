package oracle

import (
	"context"
	"encoding/json"
	"net/http"
)

// Service defines the oracle operations that must be implemented.
type Service interface {
	Decrypt(ctx context.Context, req *DecryptRequest) (*DecryptResponse, error)
	Reencrypt(ctx context.Context, req *ReencryptRequest) (*ReencryptResponse, error)
	AssertIsNil(ctx context.Context, req *IsNilRequest) (*IsNilResponse, error)
}

// Handler provides HTTP handlers for the oracle service.
type Handler struct {
	svc Service
}

// NewHandler creates a new HTTP handler for the oracle service.
func NewHandler(svc Service) *Handler {
	return &Handler{svc: svc}
}

// RegisterRoutes registers the oracle routes on an http.ServeMux.
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/decrypt", h.handleDecrypt)
	mux.HandleFunc("/reencrypt", h.handleReencrypt)
	mux.HandleFunc("/assert-is-nil", h.handleAssertIsNil)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, ErrorResponse{
		Error: err.Error(),
		Code:  status,
	})
}

func (h *Handler) handleDecrypt(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, http.ErrNotSupported)
		return
	}
	var req DecryptRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	resp, err := h.svc.Decrypt(r.Context(), &req)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h *Handler) handleReencrypt(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, http.ErrNotSupported)
		return
	}
	var req ReencryptRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	resp, err := h.svc.Reencrypt(r.Context(), &req)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h *Handler) handleAssertIsNil(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, http.ErrNotSupported)
		return
	}
	var req IsNilRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	resp, err := h.svc.AssertIsNil(r.Context(), &req)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}
