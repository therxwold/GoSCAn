package githubrepo

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestQueryDetectsExplicitUnmaintainedNotice(t *testing.T) {
	readme := base64.StdEncoding.EncodeToString([]byte("# Martini\n\nNOTE: The martini framework is no longer maintained."))
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/go-martini/martini":
			fmt.Fprint(w, `{"full_name":"go-martini/martini","html_url":"https://github.com/go-martini/martini","archived":false,"pushed_at":"2022-03-29T00:00:00Z"}`)
		case "/repos/go-martini/martini/readme":
			fmt.Fprintf(w, `{"encoding":"base64","content":%q}`, readme)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	records, err := (Client{BaseURL: srv.URL}).Query(context.Background(), []string{"github.com/go-martini/martini"}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	record := records["go-martini/martini"]
	if !record.ExplicitUnmaintained || record.MaintenanceNotice != "no longer maintained" {
		t.Fatalf("record=%+v", record)
	}
}

func TestRepositoryFromModule(t *testing.T) {
	repo, ok := RepositoryFromModule("github.com/foo/bar/submodule")
	if !ok || repo != "foo/bar" {
		t.Fatalf("repo=%q ok=%v", repo, ok)
	}
	if _, ok := RepositoryFromModule("golang.org/x/mod"); ok {
		t.Fatal("non-GitHub module unexpectedly matched")
	}
}
