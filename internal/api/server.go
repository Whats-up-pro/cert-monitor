// Package api provides HTTP handlers for the Verification Agent
package api

import (
	"cert-monitor/internal/config"
	"cert-monitor/internal/core"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"github.com/rs/cors"
)

// Server represents the HTTP API server
type Server struct {
	config    *config.Config
	validator *core.MultiDimensionalValidator
	consensus *core.ConsensusEngine
	router    *mux.Router
}

// NewServer creates a new API server
func NewServer(cfg *config.Config) *Server {
	// Create validator config
	validatorCfg := core.ValidatorConfig{
		EnableFingerprint:   cfg.Validator.EnableFingerprint,
		EnableCT:            cfg.Validator.EnableCT,
		EnableOCSP:          cfg.Validator.EnableOCSP,
		EnableDNSCAA:        cfg.Validator.EnableDNSCAA,
		EnableHistorical:    cfg.Validator.EnableHistorical,
		EnableML:            cfg.Validator.EnableML,
		TotalTimeout:        cfg.Validator.TotalTimeout,
		PerCheckTimeout:     cfg.Validator.PerCheckTimeout,
		MITMThreshold:       cfg.Validator.MITMThreshold,
		SuspiciousThreshold: cfg.Validator.SuspiciousThreshold,
		AllowCDNVariance:    cfg.Validator.AllowCDNVariance,
	}

	s := &Server{
		config:    cfg,
		validator: core.NewMultiDimensionalValidator(validatorCfg),
		router:    mux.NewRouter(),
	}

	// Initialize consensus if enabled
	if cfg.Agent.EnableConsensus {
		var agents []core.AgentEndpoint
		for i, url := range cfg.Agent.PeerAgents {
			agents = append(agents, core.AgentEndpoint{
				ID:       fmt.Sprintf("peer-%d", i),
				URL:      url,
				Enabled:  true,
				Priority: i,
			})
		}
		s.consensus = core.NewConsensusEngine(cfg.Agent.ID, agents)
	}

	s.setupRoutes()
	return s
}

// setupRoutes configures all HTTP routes
func (s *Server) setupRoutes() {
	// API v2 routes
	api := s.router.PathPrefix("/api/v2").Subrouter()

	api.HandleFunc("/verify", s.handleVerify).Methods("POST")
	api.HandleFunc("/verify-consensus", s.handleVerifyConsensus).Methods("POST")
	api.HandleFunc("/health", s.handleHealth).Methods("GET")
	api.HandleFunc("/attest", s.handleAttest).Methods("GET")
	api.HandleFunc("/info", s.handleInfo).Methods("GET")

	// Batch verification
	api.HandleFunc("/batch-verify", s.handleBatchVerify).Methods("POST")

	// CT log lookup
	api.HandleFunc("/ct-lookup", s.handleCTLookup).Methods("GET")

	// Middleware
	s.router.Use(s.loggingMiddleware)
	s.router.Use(s.recoveryMiddleware)
}

// Start starts the HTTP server
func (s *Server) Start() error {
	addr := fmt.Sprintf("%s:%d", s.config.Server.Host, s.config.Server.Port)

	// Setup CORS
	var handler http.Handler = s.router
	if s.config.Server.EnableCORS {
		c := cors.New(cors.Options{
			AllowedOrigins:   []string{"*"},
			AllowedMethods:   []string{"GET", "POST", "OPTIONS"},
			AllowedHeaders:   []string{"Content-Type", "Authorization", "X-Request-ID"},
			AllowCredentials: true,
		})
		handler = c.Handler(s.router)
	}

	server := &http.Server{
		Addr:         addr,
		Handler:      handler,
		ReadTimeout:  s.config.Server.ReadTimeout,
		WriteTimeout: s.config.Server.WriteTimeout,
	}

	log.Printf("Starting Cert-Monitor Agent v2.0 on %s", addr)
	log.Printf("Agent ID: %s, Region: %s", s.config.Agent.ID, s.config.Agent.Region)

	if s.config.Server.TLSCertFile != "" && s.config.Server.TLSKeyFile != "" {
		return server.ListenAndServeTLS(s.config.Server.TLSCertFile, s.config.Server.TLSKeyFile)
	}

	return server.ListenAndServe()
}

// handleVerify handles single domain verification
func (s *Server) handleVerify(w http.ResponseWriter, r *http.Request) {
	var req core.VerificationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.respondError(w, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}

	// Validate request
	if req.Domain == "" {
		s.respondError(w, http.StatusBadRequest, "Domain is required", "")
		return
	}

	// Set request ID if not provided
	if req.RequestID == "" {
		req.RequestID = generateRequestID()
	}
	req.Timestamp = time.Now().Unix()

	// Perform verification
	response := s.validator.Validate(r.Context(), &req)

	// Add attestation
	if s.consensus != nil {
		dataHash := core.CalculateDataHash(req.Domain, req.ClientCertFingerprint, response.Verdict)
		response.Attestation = s.consensus.CreateAttestation(dataHash)
	}

	s.respondJSON(w, http.StatusOK, response)
}

// handleVerifyConsensus handles verification with multi-agent consensus
func (s *Server) handleVerifyConsensus(w http.ResponseWriter, r *http.Request) {
	if s.consensus == nil {
		s.respondError(w, http.StatusServiceUnavailable, "Consensus not enabled", "")
		return
	}

	var req core.VerificationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.respondError(w, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}

	if req.Domain == "" {
		s.respondError(w, http.StatusBadRequest, "Domain is required", "")
		return
	}

	if req.RequestID == "" {
		req.RequestID = generateRequestID()
	}
	req.Timestamp = time.Now().Unix()

	// Perform consensus verification
	result := s.consensus.VerifyWithConsensus(r.Context(), &req)

	s.respondJSON(w, http.StatusOK, result)
}

// handleHealth handles health check requests
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	health := map[string]interface{}{
		"status":    "healthy",
		"timestamp": time.Now().Unix(),
		"agent_id":  s.config.Agent.ID,
		"region":    s.config.Agent.Region,
		"version":   "2.0.0",
	}

	// Check peer health if consensus enabled
	if s.consensus != nil {
		health["peer_health"] = s.consensus.AgentHealthCheck(r.Context())
	}

	s.respondJSON(w, http.StatusOK, health)
}

// handleAttest provides attestation proof
func (s *Server) handleAttest(w http.ResponseWriter, r *http.Request) {
	if s.consensus == nil {
		s.respondError(w, http.StatusServiceUnavailable, "Attestation not available", "")
		return
	}

	attestation := s.consensus.CreateAttestation("health-check")
	s.respondJSON(w, http.StatusOK, attestation)
}

// handleInfo provides agent information
func (s *Server) handleInfo(w http.ResponseWriter, r *http.Request) {
	info := map[string]interface{}{
		"agent_id":   s.config.Agent.ID,
		"region":     s.config.Agent.Region,
		"version":    "2.0.0",
		"features": map[string]bool{
			"fingerprint_validation": s.config.Validator.EnableFingerprint,
			"ct_log_validation":      s.config.Validator.EnableCT,
			"ocsp_validation":        s.config.Validator.EnableOCSP,
			"ml_anomaly_detection":   s.config.Validator.EnableML,
			"tofu_caching":           s.config.Cache.EnableTOFU,
			"consensus_enabled":      s.config.Agent.EnableConsensus,
		},
		"thresholds": map[string]float64{
			"mitm_threshold":       s.config.Validator.MITMThreshold,
			"suspicious_threshold": s.config.Validator.SuspiciousThreshold,
		},
	}

	s.respondJSON(w, http.StatusOK, info)
}

// BatchVerifyRequest for batch verification
type BatchVerifyRequest struct {
	Domains []string `json:"domains"`
}

// BatchVerifyResponse for batch verification
type BatchVerifyResponse struct {
	Results   map[string]*core.VerificationResponse `json:"results"`
	Summary   BatchSummary                          `json:"summary"`
	TotalTime int64                                 `json:"total_time_ms"`
}

// BatchSummary summarizes batch results
type BatchSummary struct {
	Total      int `json:"total"`
	Safe       int `json:"safe"`
	MITM       int `json:"mitm_detected"`
	Suspicious int `json:"suspicious"`
	Errors     int `json:"errors"`
}

// handleBatchVerify handles batch domain verification
func (s *Server) handleBatchVerify(w http.ResponseWriter, r *http.Request) {
	var req BatchVerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.respondError(w, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}

	if len(req.Domains) == 0 {
		s.respondError(w, http.StatusBadRequest, "At least one domain is required", "")
		return
	}

	if len(req.Domains) > 100 {
		s.respondError(w, http.StatusBadRequest, "Maximum 100 domains per batch", "")
		return
	}

	startTime := time.Now()
	results := make(map[string]*core.VerificationResponse)
	summary := BatchSummary{Total: len(req.Domains)}

	for _, domain := range req.Domains {
		verifyReq := &core.VerificationRequest{
			Domain:    domain,
			RequestID: generateRequestID(),
			Timestamp: time.Now().Unix(),
		}

		resp := s.validator.Validate(r.Context(), verifyReq)
		results[domain] = resp

		switch resp.Verdict {
		case core.VerdictSafe:
			summary.Safe++
		case core.VerdictMITMDetected:
			summary.MITM++
		case core.VerdictSuspicious:
			summary.Suspicious++
		default:
			summary.Errors++
		}
	}

	response := BatchVerifyResponse{
		Results:   results,
		Summary:   summary,
		TotalTime: time.Since(startTime).Milliseconds(),
	}

	s.respondJSON(w, http.StatusOK, response)
}

// CTLookupResponse for CT log lookup
type CTLookupResponse struct {
	Domain       string   `json:"domain"`
	Certificates []CTCert `json:"certificates"`
	TotalCount   int      `json:"total_count"`
}

// CTCert represents a CT log certificate entry
type CTCert struct {
	IssuerName   string `json:"issuer_name"`
	CommonName   string `json:"common_name"`
	NotBefore    string `json:"not_before"`
	NotAfter     string `json:"not_after"`
	SerialNumber string `json:"serial_number"`
}

// handleCTLookup handles CT log lookups by domain
func (s *Server) handleCTLookup(w http.ResponseWriter, r *http.Request) {
	domain := r.URL.Query().Get("domain")
	if domain == "" {
		s.respondError(w, http.StatusBadRequest, "Domain parameter is required", "")
		return
	}

	// This would query CT logs - simplified response
	response := CTLookupResponse{
		Domain:       domain,
		Certificates: []CTCert{},
		TotalCount:   0,
	}

	s.respondJSON(w, http.StatusOK, response)
}

// Middleware functions

func (s *Server) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		log.Printf("[%s] %s %s", r.Method, r.URL.Path, r.RemoteAddr)
		next.ServeHTTP(w, r)
		log.Printf("[%s] %s completed in %v", r.Method, r.URL.Path, time.Since(start))
	})
}

func (s *Server) recoveryMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				log.Printf("Panic recovered: %v", err)
				s.respondError(w, http.StatusInternalServerError, "Internal server error", "")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// Helper functions

func (s *Server) respondJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func (s *Server) respondError(w http.ResponseWriter, status int, message, details string) {
	response := map[string]string{
		"error":   message,
		"details": details,
	}
	s.respondJSON(w, status, response)
}

func generateRequestID() string {
	return fmt.Sprintf("req-%d", time.Now().UnixNano())
}
