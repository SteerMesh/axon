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
	return InstallWithEnv(executable, home, nil)
}

// InstallWithEnv writes a per-user launchd plist or systemd unit. Non-empty env
// entries are embedded so the agent inherits them at service start (e.g.
// AXON_RELAY_URL for serve after reboot).
func InstallWithEnv(executable, home string, env map[string]string) (string, error) {
	return installForOS(runtime.GOOS, executable, home, env)
}

func installForOS(goos, executable, home string, env map[string]string) (string, error) {
	switch goos {
	case "darwin":
		path := filepath.Join(home, "Library", "LaunchAgents", "com.steermesh.axon.plist")
		executable = xmlText(executable)
		home = xmlText(home)
		envBlock := ""
		if block := darwinEnvironmentVariables(env); block != "" {
			envBlock = "\n" + block
		}
		content := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>com.steermesh.axon</string>
<key>ProgramArguments</key><array><string>%s</string><string>serve</string></array>
<key>RunAtLoad</key><true/><key>KeepAlive</key><true/>%s
<key>StandardOutPath</key><string>%s/.mesh/axon/agent.log</string>
<key>StandardErrorPath</key><string>%s/.mesh/axon/agent.err.log</string>
</dict></plist>
`, executable, envBlock, home, home)
		return write(path, content)
	case "linux":
		path := filepath.Join(home, ".config", "systemd", "user", "mesh-axon.service")
		envLines := linuxEnvironmentLines(env)
		content := fmt.Sprintf(`[Unit]
Description=Mesh Axon Agent
After=network-online.target

[Service]
ExecStart=%s serve
%sRestart=on-failure
RestartSec=5

[Install]
WantedBy=default.target
`, strconv.Quote(executable), envLines)
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

func darwinEnvironmentVariables(env map[string]string) string {
	if len(env) == 0 {
		return ""
	}
	var b bytes.Buffer
	b.WriteString("<key>EnvironmentVariables</key><dict>")
	for key, value := range env {
		if value == "" {
			continue
		}
		b.WriteString("<key>")
		b.WriteString(xmlText(key))
		b.WriteString("</key><string>")
		b.WriteString(xmlText(value))
		b.WriteString("</string>")
	}
	b.WriteString("</dict>")
	return b.String()
}

func linuxEnvironmentLines(env map[string]string) string {
	if len(env) == 0 {
		return ""
	}
	var b bytes.Buffer
	for key, value := range env {
		if value == "" {
			continue
		}
		fmt.Fprintf(&b, "Environment=%s=%s\n", key, value)
	}
	return b.String()
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
