package httpserver

import (
	"errors"
	"io"
	"net"
	"net/http"
	"runtime/debug"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

const (
	allowedMethods    = "GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS"
	maxClients        = 10_000
	evictionBatchSize = 128
	staleClientAfter  = 5 * time.Minute
)

type requestInfo struct {
	state       *serverState
	start       time.Time
	kind        string
	rule        string
	requestBody *requestBodyLog
}

type statusRecorder struct {
	http.ResponseWriter
	status int
	info   requestInfo
}

func (w *statusRecorder) WriteHeader(status int) {
	if w.status != 0 {
		return
	}
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *statusRecorder) Write(body []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(body)
}

func recoverMiddleware(s *Server, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		state := s.state.Load()
		if state == nil {
			state = &serverState{}
		}
		recorder := &statusRecorder{
			ResponseWriter: w,
			info:           requestInfo{state: state, start: time.Now()},
		}

		defer func() {
			if recovered := recover(); recovered != nil {
				if recovered == http.ErrAbortHandler {
					panic(recovered)
				}
				recorder.info.kind = "panic"
				if recorder.status == 0 {
					http.Error(recorder, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				}
				s.logger.ErrorContext(r.Context(), "HTTP handler panic",
					"panic", recovered,
					"stack", string(debug.Stack()),
				)
			}
			s.finishRequest(recorder, r, &recorder.info)
		}()

		next.ServeHTTP(recorder, r)
	})
}

func rateLimitMiddleware(limiters *clientLimiters, next http.Handler) http.Handler {
	if !limiters.enabled {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !limiters.allow(clientIP(r.RemoteAddr)) {
			w.(*statusRecorder).info.kind = "ratelimited"
			w.Header().Set("Retry-After", "1")
			http.Error(w, http.StatusText(http.StatusTooManyRequests), http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func methodMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !methodAllowed(r.Method) {
			w.(*statusRecorder).info.kind = "badmethod"
			w.Header().Set("Allow", allowedMethods)
			http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func bodyLimitMiddleware(maxBytes int64, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
		if methodHasBody(r.Method) {
			destination := io.Writer(io.Discard)
			recorder := w.(*statusRecorder)
			capture, bodyLog := prepareRequestBodyCapture(recorder.info.state.cfg, r)
			recorder.info.requestBody = bodyLog
			if capture != nil {
				destination = capture
			}
			_, err := io.Copy(destination, r.Body)
			if capture != nil {
				recorder.info.requestBody = capture.finish()
			}
			if err != nil {
				var tooLarge *http.MaxBytesError
				if errors.As(err, &tooLarge) {
					w.(*statusRecorder).info.kind = "oversized"
					w.Header().Set("Connection", "close")
					r.Close = true
					http.Error(w, http.StatusText(http.StatusRequestEntityTooLarge), http.StatusRequestEntityTooLarge)
					return
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}

func methodAllowed(method string) bool {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut,
		http.MethodPatch, http.MethodDelete, http.MethodOptions:
		return true
	default:
		return false
	}
}

func methodHasBody(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	default:
		return false
	}
}

type clientLimiter struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

type clientLimiters struct {
	mu      sync.Mutex
	clients map[string]*clientLimiter
	limit   rate.Limit
	burst   int
	enabled bool
}

func (l *clientLimiters) configure(requestsPerSecond float64, burst int) {
	if requestsPerSecond <= 0 {
		return
	}
	l.enabled = true
	l.limit = rate.Limit(requestsPerSecond)
	l.burst = burst
	l.clients = make(map[string]*clientLimiter)
}

func (l *clientLimiters) allow(client string) bool {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()

	entry := l.clients[client]
	if entry == nil {
		if len(l.clients) >= maxClients {
			l.evictOldest(now)
		}
		entry = &clientLimiter{limiter: rate.NewLimiter(l.limit, l.burst)}
		l.clients[client] = entry
	}
	entry.lastSeen = now
	return entry.limiter.AllowN(now, 1)
}

func (l *clientLimiters) evictOldest(now time.Time) {
	var sampled [evictionBatchSize]string
	sampledCount := 0
	staleCount := 0

	// ponytail: approximate LRU; strict oldest-scan not worth the lock hold
	for key, entry := range l.clients {
		sampled[sampledCount] = key
		sampledCount++
		if now.Sub(entry.lastSeen) >= staleClientAfter {
			delete(l.clients, key)
			staleCount++
		}
		if sampledCount == evictionBatchSize {
			break
		}
	}
	if staleCount != 0 {
		return
	}
	for _, key := range sampled[:sampledCount] {
		delete(l.clients, key)
	}
}

func clientIP(remoteAddress string) string {
	host, _, err := net.SplitHostPort(remoteAddress)
	if err != nil {
		return "unknown"
	}
	return host
}
