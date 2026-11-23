package main

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

type containerRow struct {
	Name         string `json:"name"`
	Service      string `json:"service"`
	State        string `json:"state"`
	Health       string `json:"health"`
	RestartCount int    `json:"restart_count"`
	Image        string `json:"image"`
	ImageID      string `json:"image_id"`
	StartedAt    string `json:"started_at"`
}

type envDiff struct {
	Key       string `json:"key"`
	Sensitive bool   `json:"sensitive"`
	Chain     string `json:"chain"`
	Running   string `json:"running"`
}

type driftRow struct {
	Service    string    `json:"service"`
	ImageMatch bool      `json:"image_match"`
	NotRunning bool      `json:"not_running,omitempty"`
	EnvDiff    []envDiff `json:"env_diff"`
}

type diskRow struct {
	Mount      string `json:"mount"`
	UsedPct    int    `json:"used_pct"`
	AvailBytes uint64 `json:"avail_bytes"`
}

type certRow struct {
	Path     string `json:"path"`
	NotAfter string `json:"not_after"`
	DaysLeft int    `json:"days_left"`
}

type snapshot struct {
	At           string         `json:"at"`
	AgentVersion string         `json:"agent_version"`
	Containers   []containerRow `json:"containers"`
	Drift        any            `json:"drift"`
	Disk         []diskRow      `json:"disk"`
	Certs        []certRow      `json:"certs"`
	Errors       []string       `json:"errors"`
}

func jsonIndent(v any) ([]byte, error) { return json.MarshalIndent(v, "", "  ") }

// inferProject 推断 compose 项目名：.upgrade/project-name > 与 project-directory 匹配的容器标签 > docker-compose。
func (a *agent) inferProject(cs []container) string {
	if b, err := os.ReadFile(filepath.Join(a.deployDir, ".upgrade", "project-name")); err == nil {
		if p := strings.TrimSpace(string(b)); projectRe.MatchString(p) {
			return p
		}
	}
	if b, err := os.ReadFile(filepath.Join(a.deployDir, ".upgrade", "project-directory")); err == nil {
		pd := strings.TrimSpace(string(b))
		for _, c := range cs {
			if c.WorkingDir != "" && c.WorkingDir == pd && projectRe.MatchString(c.Project) {
				return c.Project
			}
		}
	}
	return "docker-compose"
}

func (a *agent) collectContainers(ctx context.Context) ([]containerRow, error) {
	cs, err := listAllContainers(ctx)
	if err != nil {
		return nil, err
	}
	proj := a.inferProject(cs)
	var mine []container
	var ids []string
	for _, c := range cs {
		if c.Project == proj && c.Service != "" {
			mine = append(mine, c)
			ids = append(ids, c.ID)
		}
	}
	info, err := inspectContainers(ctx, ids)
	if err != nil {
		return nil, err
	}
	rows := []containerRow{}
	for _, c := range mine {
		r := containerRow{Name: c.Name, Service: c.Service, State: c.State, Image: c.Image}
		for id, i := range info {
			if id == c.ID || strings.HasPrefix(id, c.ID) || strings.HasPrefix(c.ID, id) {
				r.State = i.State.Status
				r.Health = i.health()
				r.RestartCount = i.RestartCount
				r.ImageID = i.Image
				r.StartedAt = i.State.StartedAt
				break
			}
		}
		rows = append(rows, r)
	}
	return rows, nil
}

func (a *agent) collectDisk() []diskRow {
	paths := []string{"/", "/var/lib/docker", a.deployDir, a.dir}
	seen := map[uint64]bool{}
	rows := []diskRow{}
	for _, p := range paths {
		var st syscall.Stat_t
		if err := syscall.Stat(p, &st); err != nil {
			continue
		}
		dev := uint64(st.Dev)
		if seen[dev] {
			continue
		}
		seen[dev] = true
		var fs syscall.Statfs_t
		if err := syscall.Statfs(p, &fs); err != nil || fs.Blocks == 0 {
			continue
		}
		bs := uint64(fs.Bsize)
		total := uint64(fs.Blocks) * bs
		avail := uint64(fs.Bavail) * bs
		free := uint64(fs.Bfree) * bs
		used := total - free
		denom := used + avail
		pct := 0
		if denom > 0 {
			pct = int((used*100 + denom - 1) / denom)
		}
		rows = append(rows, diskRow{Mount: p, UsedPct: pct, AvailBytes: avail})
	}
	return rows
}

func (a *agent) collectCerts() []certRow {
	var files []string
	for _, pat := range []string{
		filepath.Join(a.deployDir, "tls", "*.crt"),
		filepath.Join(a.deployDir, "tls", "*.pem"),
		"/etc/jjdguard/*.crt",
	} {
		m, _ := filepath.Glob(pat)
		files = append(files, m...)
	}
	rows := []certRow{}
	now := a.now()
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		for {
			var blk *pem.Block
			blk, b = pem.Decode(b)
			if blk == nil {
				break
			}
			if blk.Type != "CERTIFICATE" {
				continue
			}
			c, err := x509.ParseCertificate(blk.Bytes)
			if err != nil {
				continue
			}
			rows = append(rows, certRow{Path: f, NotAfter: c.NotAfter.UTC().Format(time.RFC3339),
				DaysLeft: int(c.NotAfter.Sub(now).Hours() / 24)})
			break // 只看叶子（第一张）
		}
	}
	return rows
}

func (a *agent) buildSnapshot(ctx context.Context) snapshot {
	s := snapshot{At: a.now().UTC().Format(time.RFC3339), AgentVersion: agentVersion,
		Containers: []containerRow{}, Errors: []string{}}
	rows, err := a.collectContainers(ctx)
	if err != nil {
		s.Errors = append(s.Errors, "containers: "+redactText(err.Error()))
	} else {
		s.Containers = rows
	}
	items, derr := a.collectDrift(ctx)
	if derr != "" {
		s.Drift = map[string]string{"error": derr}
	} else {
		s.Drift = items
	}
	s.Disk = a.collectDisk()
	s.Certs = a.collectCerts()
	return s
}

func (a *agent) writeSnapshot(ctx context.Context) error {
	s := a.buildSnapshot(ctx)
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return atomicWrite(filepath.Join(a.dir, "snapshot", "latest.json"), b, 0o644)
}
