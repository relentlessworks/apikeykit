package api

import (
	"encoding/json"
	"net/http"
	"strings"
)

// wantsJSON checks if the client wants JSON responses.
func wantsJSON(r *http.Request) bool {
	if r.URL.Query().Get("format") == "json" {
		return true
	}
	accept := r.Header.Get("Accept")
	return strings.Contains(accept, "application/json")
}

// writeRecord writes a single record as plain text or JSON.
func writeRecord(w http.ResponseWriter, r *http.Request, fields map[string]interface{}) {
	if wantsJSON(r) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(fields)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	var sb strings.Builder
	for k, v := range fields {
		sb.WriteString(k)
		sb.WriteString("=")
		switch val := v.(type) {
		case string:
			sb.WriteString(val)
		case []string:
			sb.WriteString(strings.Join(val, ","))
		default:
			b, _ := json.Marshal(val)
			sb.Write(b)
		}
		sb.WriteString(" ")
	}
	s := sb.String()
	if len(s) > 0 && s[len(s)-1] == ' ' {
		s = s[:len(s)-1]
	}
	w.Write([]byte(s))
}

// writeRecords writes multiple records as plain text (one per line) or JSON.
func writeRecords(w http.ResponseWriter, r *http.Request, records []map[string]interface{}) {
	if wantsJSON(r) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(records)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	for _, rec := range records {
		var sb strings.Builder
		for k, v := range rec {
			sb.WriteString(k)
			sb.WriteString("=")
			switch val := v.(type) {
			case string:
				sb.WriteString(val)
			case []string:
				sb.WriteString(strings.Join(val, ","))
			default:
				b, _ := json.Marshal(val)
				sb.Write(b)
			}
			sb.WriteString(" ")
		}
		s := sb.String()
		if len(s) > 0 && s[len(s)-1] == ' ' {
			s = s[:len(s)-1]
		}
		w.Write([]byte(s + "\n"))
	}
}

// writeError writes an error response with a hint.
func writeError(w http.ResponseWriter, r *http.Request, code int, msg, hint string) {
	if wantsJSON(r) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(code)
		json.NewEncoder(w).Encode(map[string]string{
			"error": msg,
			"hint":  hint,
		})
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(code)
	resp := "error: " + msg
	if hint != "" {
		resp += " | hint: " + hint
	}
	w.Write([]byte(resp + "\n"))
}

// writeText writes a plain text response.
func writeText(w http.ResponseWriter, text string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write([]byte(text))
}

// getBearer extracts the bearer token from the Authorization header.
func getBearer(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimPrefix(auth, "Bearer ")
	}
	return ""
}

// parseScopes parses a comma-separated scope string into a slice.
func parseScopes(s string) []string {
	if s == "" {
		return []string{"*"}
	}
	parts := strings.Split(s, ",")
	var out []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return []string{"*"}
	}
	return out
}
