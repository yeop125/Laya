//go:build !cgo

package main

// Desktop sidecar: the same engine the iOS bridge links in, as a standalone
// executable the desktop app (JVM) launches as a child process. Built with
// CGO_ENABLED=0, which drops bridge.go (it imports "C") and picks this file
// up instead, so it cross-compiles for Windows from any host:
//
//	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -o laya_wg.exe .
//
// Protocol, one JSON object per line:
//
//	stdin  <- {"profile":"<wg-quick .conf text>","user":"...","pass":"...","openLocal":true}
//	stdout -> {"ok":true,"port":12345}   or   {"ok":false,"error":"..."}
//
// The engine then runs until stdin reaches EOF, which is what happens when the
// parent process exits for any reason (including a crash), so the tunnel never
// outlives the app. Nothing secret is ever written to stdout or stderr.

import (
	"bufio"
	"encoding/json"
	"io"
	"os"
)

type sidecarRequest struct {
	Profile string `json:"profile"`
	User    string `json:"user"`
	Pass    string `json:"pass"`
	// OpenLocal: no login on the loopback listener (see EngineOptions).
	OpenLocal bool `json:"openLocal"`
}

func sidecarReply(v map[string]any) {
	b, _ := json.Marshal(v)
	os.Stdout.Write(append(b, '\n'))
}

func main() {
	in := bufio.NewReaderSize(os.Stdin, 64*1024)
	line, err := in.ReadBytes('\n')
	if err != nil && len(line) == 0 {
		sidecarReply(map[string]any{"ok": false, "error": "no request"})
		os.Exit(2)
	}
	var req sidecarRequest
	if err := json.Unmarshal(line, &req); err != nil {
		sidecarReply(map[string]any{"ok": false, "error": "invalid request"})
		os.Exit(2)
	}
	p, err := ParseProfile(req.Profile)
	req.Profile = ""
	if err != nil {
		sidecarReply(map[string]any{"ok": false, "error": err.Error()})
		os.Exit(1)
	}
	e, err := StartEngine(p, req.User, req.Pass, EngineOptions{OpenLocal: req.OpenLocal})
	if err != nil {
		sidecarReply(map[string]any{"ok": false, "error": err.Error()})
		os.Exit(1)
	}
	sidecarReply(map[string]any{"ok": true, "port": e.Port()})
	// Block until the parent goes away.
	io.Copy(io.Discard, in)
	e.Close()
}
