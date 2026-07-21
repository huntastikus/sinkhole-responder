package admin

import (
	"log/slog"
	"net/http"
	"strconv"
	"time"
)

const (
	defaultLogLimit = 200
	maxLogLimit     = 1000
)

type logRecordResponse struct {
	Time  string         `json:"time"`
	Level string         `json:"level"`
	Msg   string         `json:"msg"`
	Attrs map[string]any `json:"attrs"`
}

type logsResponse struct {
	Records []logRecordResponse `json:"records"`
}

func (s *Server) handleLogs(w http.ResponseWriter, r *http.Request) {
	minLevel, ok := logLevel(r.URL.Query().Get("level"))
	if !ok {
		writeConfigError(w, http.StatusBadRequest, "invalid log level")
		return
	}

	limit, err := logLimit(r.URL.Query().Get("limit"))
	if err != nil {
		writeConfigError(w, http.StatusBadRequest, "invalid log limit")
		return
	}

	records := make([]logRecordResponse, 0)
	if s.deps.LogBuf != nil {
		for _, record := range s.deps.LogBuf.Snapshot(minLevel, limit) {
			records = append(records, logRecordResponse{
				Time:  record.Time.Format(time.RFC3339),
				Level: record.Level,
				Msg:   record.Msg,
				Attrs: record.Attrs,
			})
		}
	}

	writeConfigJSON(w, http.StatusOK, logsResponse{Records: records})
}

func logLevel(value string) (slog.Level, bool) {
	switch value {
	case "":
		return slog.LevelInfo, true
	case "debug":
		return slog.LevelDebug, true
	case "info":
		return slog.LevelInfo, true
	case "warn":
		return slog.LevelWarn, true
	case "error":
		return slog.LevelError, true
	default:
		return 0, false
	}
}

func logLimit(value string) (int, error) {
	if value == "" {
		return defaultLogLimit, nil
	}
	limit, err := strconv.Atoi(value)
	if err != nil {
		return 0, err
	}
	return min(max(limit, 1), maxLogLimit), nil
}
