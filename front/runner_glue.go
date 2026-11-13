package main

import (
	"fmt"
	"io"
	"os"
)

// The few places the function runner joins the rest of the front. Everything here is called from proxy.go, control.go, lambda_heavy.go or
// main.go; the logic lives in the runner_*.go files.

// the helper's root is read-only and /tmp is its one writable path, so that is where the socket lives unless ROVARA_AWS_RUNNER_SOCKET says otherwise
const defaultRunnerSocket = "/tmp/rovara-runner/runner.sock"

// lambdaInspectLimit: the most of a Lambda request body that is read whole. The runner keeps whole packages (Lambda's 50 MB zip, as base64).
func (s *Server) lambdaInspectLimit() int64 {
	if s.runner != nil {
		return runnerBodyCap
	}
	return lambdaInspectCap
}

// runnerRewriteKind: the answers the runner reads or changes. Called only when the runner is on.
func runnerRewriteKind(id identified) rewriteKind {
	switch id.Service.Key {
	case "lambda":
		if overlayOps[id.Operation] || id.Operation == "PublishLayerVersion" {
			return rwRunnerOverlay
		}
	case "eventbridge", "events":
		if id.Operation == "ListTargetsByRule" {
			return rwRunnerHide
		}
	case "s3":
		if id.Operation == "ListBuckets" {
			return rwRunnerHide
		}
	case "iam":
		if id.Operation == "ListRoles" || id.Operation == "GetAccountAuthorizationDetails" {
			return rwRunnerHide
		}
	}
	return rwNone
}

// runnerAfter runs when the engine accepted a Lambda request: the plan is committed, a deleted function leaves the registry, and the answer's
// function configurations are the real ones (never the stub's). It returns the answer to send.
func (s *Server) runnerAfter(op, rawPath, qualifier string, plan *runnerPlan, data []byte, canRewrite bool) []byte {
	if plan != nil && plan.commit != nil {
		if plan.gen != s.runner.genNum() {
			// a reset ended the generation this request started in: its function belongs to no registry, and holds no package
			if plan.abort != nil {
				plan.abort()
			}
			plan.commit = nil
		} else {
			plan.commit(data)
		}
	}
	if op == "DeleteFunction" {
		if segs := splitPath(rawPath); len(segs) > 2 {
			name, q := splitInvokeName(segs[2])
			if qualifier != "" {
				q = qualifier
			}
			s.runner.dropFunction(name, q)
		}
	}
	if canRewrite && overlayOps[op] {
		data = s.runner.overlay(op, data)
	}
	return data
}

// runnerHandles: whether the runner runs this function (so the "cannot run" record of the detector would be untrue). Native x86-64 code and
// container images are taken over too, but they still cannot run, and stay recorded.
func (s *Server) runnerHandles(name, reason string) bool {
	if s.runner == nil {
		return false
	}
	switch reason {
	case "native-code", "runtime", "long-timeout", "x86-native":
		return s.runner.reg.isTaken(name)
	}
	return false
}

// runnerState is the word GET /_rovara/lambda/heavy gives for "runner".
func (s *Server) runnerState() string {
	switch {
	case s.runner == nil:
		return "not available"
	case s.runner.hub.connected():
		return "connected"
	}
	return "disconnected"
}

// runnerPipeMain is `front runner-pipe [socket]`: the worker's end of the runner pipe.
func runnerPipeMain(args []string, getenv func(string) string) int {
	path := defaultRunnerSocket
	if v := getenv(envRunnerSocket); v != "" {
		path = v
	}
	if len(args) > 0 && args[0] != "" {
		path = args[0]
	}
	if err := runnerPipe(path, os.Stdin, os.Stdout); err != nil && err != io.EOF {
		fmt.Fprintln(os.Stderr, "runner-pipe:", sanitizeErr(err))
		return 1
	}
	return 0
}
