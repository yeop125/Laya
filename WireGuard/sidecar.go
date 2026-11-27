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
	"runtime"
	"syscall"
	"time"
)

type sidecarRequest struct {
	Profile string `json:"profile"`
	User    string `json:"user"`
	Pass    string `json:"pass"`
	// OpenLocal: no login on the loopback listener (see EngineOptions).
	OpenLocal bool `json:"openLocal"`
	// ParentPid: the app's process. The engine also exits when it is gone, not only when stdin
	// closes: a process the app started later (a browser it opened) can inherit the pipe's write
	// end on Windows and keep stdin open after the app has exited.
	ParentPid int `json:"parentPid"`
}

func watchParent(pid int) {
	p, err := os.FindProcess(pid)
	if err != nil {
		os.Exit(0)
	}
	if runtime.GOOS == "windows" {
		// On Windows FindProcess opens a handle that can be waited on for any process.
		p.Wait()
		os.Exit(0)
	}
	for {
		time.Sleep(3 * time.Second)
		if p.Signal(syscall.Signal(0)) != nil {
			os.Exit(0)
		}
	}
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
	if req.ParentPid > 0 {
		go watchParent(req.ParentPid)
	}
	sidecarReply(map[string]any{"ok": true, "port": e.Port()})
	// Block until the parent goes away.
	io.Copy(io.Discard, in)
	e.Close()
}
