package sanitize

import (
	"html"
	"net/http"
	"regexp"
	"strings"
)

func All(r *http.Request) {
	q := r.URL.Query()
	for k, vals := range q {
		for i, v := range vals {
			q[k][i] = Clean(v)
		}
	}
	r.URL.RawQuery = q.Encode()
	if r.Method == "POST" || r.Method == "PUT" {
		r.ParseForm()
		for k, vals := range r.Form {
			for i, v := range vals {
				r.Form[k][i] = Clean(v)
			}
		}
	}
	for k, vals := range r.Header {
		for i, v := range vals {
			r.Header[k][i] = Clean(v)
		}
	}
	for _, c := range r.Cookies() {
		c.Value = Clean(c.Value)
	}
}

func Clean(s string) string {
	s = strings.ReplaceAll(s, "\x00", "")
	s = strings.TrimSpace(s)
	s = strings.Map(func(r rune) rune { if r < 32 { return -1 }; return r }, s)
	s = html.EscapeString(s)
	s = strings.ReplaceAll(s, "'", "&#39;")
	s = strings.ReplaceAll(s, `"`, "&#34;")
	s = strings.ReplaceAll(s, "\\", "")
	s = regexp.MustCompile(`--|\b(AND|OR)\b.*?\b(=|>|<)\b`).ReplaceAllString(s, "")
	s = regexp.MustCompile(`;`).ReplaceAllString(s, "")
	s = regexp.MustCompile(`(?i)\b(UNION|SELECT|INSERT|DELETE|UPDATE|DROP|CREATE|ALTER|TRUNCATE|EXEC)\b`).ReplaceAllString(s, "")
	s = regexp.MustCompile(`(?i)javascript:`).ReplaceAllString(s, "")
	s = regexp.MustCompile(`(?i)on\w+\s*=`).ReplaceAllString(s, "")
	s = regexp.MustCompile(`(?i)base64,?[a-zA-Z0-9+/=]*`).ReplaceAllString(s, "")
	s = regexp.MustCompile(`0x[0-9a-fA-F]+`).ReplaceAllString(s, "")
	s = regexp.MustCompile(`(?i)<.*?>`).ReplaceAllString(s, "")
	s = regexp.MustCompile(`(?i)(data|vbscript|file):`).ReplaceAllString(s, "")
	return s
}

func IsMalicious(r *http.Request) bool {
	check := func(s string) bool {
		s = strings.ToLower(s)
		if strings.Contains(s, "<script") || strings.Contains(s, "javascript:") || strings.Contains(s, "union select") {
			return true
		}
		if regexp.MustCompile(`(?i)or\s+\d+=\d+`).MatchString(s) {
			return true
		}
		if regexp.MustCompile(`(?i)drop\s+table`).MatchString(s) {
			return true
		}
		return false
	}
	for _, vals := range r.URL.Query() {
		for _, v := range vals {
			if check(v) {
				return true
			}
		}
	}
	r.ParseForm()
	for _, vals := range r.Form {
		for _, v := range vals {
			if check(v) {
				return true
			}
		}
	}
	for _, vals := range r.Header {
		for _, v := range vals {
			if check(v) {
				return true
			}
		}
	}
	for _, c := range r.Cookies() {
		if check(c.Value) {
			return true
		}
	}
	return false
}