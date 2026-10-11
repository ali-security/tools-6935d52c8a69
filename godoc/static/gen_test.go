// Copyright 2018 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package static

import (
	"bytes"
	"io/ioutil"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"unicode"
)

func TestStaticIsUpToDate(t *testing.T) {
	if runtime.GOOS == "android" {
		t.Skip("files not available on android")
	}
	oldBuf, err := ioutil.ReadFile("static.go")
	if err != nil {
		t.Fatalf("error while reading static.go: %v\n", err)
	}

	newBuf, err := Generate()
	if err != nil {
		t.Fatalf("error while generating static.go: %v\n", err)
	}

	// Generate stamps time.Now().Year() into the copyright header on the
	// first line, so the committed static.go only matches in the year it was
	// generated. Compare everything after the first line.
	if bytes.Compare(dropFirstLine(oldBuf), dropFirstLine(newBuf)) != 0 {
		t.Error(`static.go is stale.  Run:
  $ go generate golang.org/x/tools/godoc/static
  $ git diff
to see the differences.`)

	}
}

// dropFirstLine returns b with everything up to and including the first
// newline removed.
func dropFirstLine(b []byte) []byte {
	if i := bytes.IndexByte(b, '\n'); i >= 0 {
		return b[i+1:]
	}
	return b
}

// TestAppendQuote ensures that AppendQuote produces a valid literal.
func TestAppendQuote(t *testing.T) {
	var in, out bytes.Buffer
	for r := rune(0); r < unicode.MaxRune; r++ {
		in.WriteRune(r)
	}
	appendQuote(&out, in.Bytes())
	in2, err := strconv.Unquote(out.String())
	if err != nil {
		t.Fatalf("AppendQuote produced invalid string literal: %v", err)
	}
	if got, want := in2, in.String(); got != want {
		t.Fatal("AppendQuote modified string") // no point printing got/want: huge
	}
}

// TestJQueryXSSHardening checks that the jQuery served by godoc carries the
// fixes for the jQuery 1.8.2 XSS family (CVE-2012-6708, sonatype-2014-0026,
// CVE-2015-9251, CVE-2019-11358, CVE-2020-11022, CVE-2020-11023 and
// CVE-2020-7656).
func TestJQueryXSSHardening(t *testing.T) {
	js, ok := Files["jquery.js"]
	if !ok {
		t.Fatal("jquery.js is not embedded in static.go")
	}

	// CVE-2012-6708, sonatype-2014-0026: jQuery(str) must treat str as HTML
	// only when it starts with "<". Markup that follows selector text (for
	// example from $(location.hash)) must not be parsed as HTML, which would
	// run its event handlers.
	m := regexp.MustCompile(`=/(\^\(\?:[^/]*\(<\[\\w\\W\]\+>\)[^/]*)/,`).FindStringSubmatch(js)
	if m == nil {
		t.Fatal("rquickExpr not found in jquery.js")
	}
	quickExpr, err := regexp.Compile(m[1])
	if err != nil {
		t.Fatalf("rquickExpr %q: %v", m[1], err)
	}
	isHTML := func(s string) bool {
		sm := quickExpr.FindStringSubmatch(s)
		return sm != nil && sm[1] != ""
	}
	for _, sel := range []string{
		"p:contains('<img src=x onerror=alert(1)>')",
		"a[title='<svg onload=alert(1)>']",
		"div <img src=x onerror=alert(1)>",
		" <img src=x onerror=alert(1)>",
	} {
		if isHTML(sel) {
			t.Errorf("jQuery(%q) is parsed as HTML", sel)
		}
	}
	if !isHTML("<div>x</div>") {
		t.Error(`jQuery("<div>x</div>") is no longer parsed as HTML`)
	}
	if sm := quickExpr.FindStringSubmatch("#main"); sm == nil || sm[2] != "main" {
		t.Error(`jQuery("#main") is no longer an ID lookup`)
	}

	// CVE-2015-9251: a cross-domain $.ajax response labelled text/javascript
	// must not be evaluated as script.
	if !regexp.MustCompile(`ajaxPrefilter\(function\(\w+\)\{\w+\.crossDomain&&\(\w+\.contents\.script=!1\)\}\)`).MatchString(js) {
		t.Error("cross-domain ajax responses are still evaluated as script")
	}

	// CVE-2019-11358: $.extend(true, {}, JSON.parse('{"__proto__":{"x":1}}'))
	// must not merge into Object.prototype.
	if !regexp.MustCompile(`if\(\w+==="__proto__"\|\|\w+===\w+\)continue;`).MatchString(js) {
		t.Error("jQuery.extend does not skip the __proto__ key")
	}

	// CVE-2020-11022: HTML passed to .html()/.append() must not be rewritten
	// by expanding self-closing tags, which turns
	// "<style><style/><img src=x onerror=alert(1)>" into live markup.
	if strings.Contains(js, `"<$1></$2>"`) {
		t.Error("jquery.js still expands self-closing tags in HTML strings")
	}

	// CVE-2020-11023: <option> markup must not be wrapped in
	// <select multiple> unconditionally, which turns
	// "<option><style></option></select><img src=x onerror=alert(1)></style>"
	// into live markup.
	if regexp.MustCompile(`[{,]option:\[1,"<select multiple='multiple'>"`).MatchString(js) {
		t.Error("wrapMap unconditionally wraps <option> in <select multiple>")
	}

	// CVE-2020-7656: .load("url selector") must not strip scripts from the
	// response with the rscript regexp, which misses "</script >".
	if regexp.MustCompile(`\.append\(\w+\.replace\(\w+,""\)\)\.find\(`).MatchString(js) {
		t.Error(".load() strips scripts with a regexp that misses </script >")
	}
	if !regexp.MustCompile(`\.append\(\w+\.parseHTML\(\w+\)\)\.find\(`).MatchString(js) {
		t.Error(".load() does not parse the response with parseHTML")
	}
}
