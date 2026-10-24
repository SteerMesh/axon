package service

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
)

func Install(executable, home string) (string, error) {
	return installForOS(runtime.GOOS, executable, home)
}

func installForOS(goos, executable, home string) (string, error) {
	switch goos {
	case "darwin":
		path := filepath.Join(home, "Library", "LaunchAgents", "com.steermesh.axon.plist")
		executable = xmlText(executable)
		home = xmlText(home)
		content := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>com.steermesh.axon</string>
<key>ProgramArguments</key><array><string>%s</string><string>serve</string></array>
<key>RunAtLoad</key><true/><key>KeepAlive</key><true/>
<key>StandardOutPath</key><string>%s/.mesh/axon/agent.log</string>
<key>StandardErrorPath</key><string>%s/.mesh/axon/agent.err.log</string>
</dict></plist>
`, executable, home, home)
		return write(path, content)
	case "linux":
		path := filepath.Join(home, ".config", "systemd", "user", "mesh-axon.service")
		content := fmt.Sprintf(`[Unit]
Description=Mesh Axon Agent
After=network-online.target

[Service]
ExecStart=%s serve
Restart=on-failure
RestartSec=5

[Install]
WantedBy=default.target
`, strconv.Quote(executable))
		return write(path, content)
	default:
		return "", fmt.Errorf("service installation is not supported on %s", goos)
	}
}

func xmlText(value string) string {
	var result bytes.Buffer
	_ = xml.EscapeText(&result, []byte(value))
	return result.String()
}

func write(path, content string) (string, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", err
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		return "", err
	}
	return path, nil
}
