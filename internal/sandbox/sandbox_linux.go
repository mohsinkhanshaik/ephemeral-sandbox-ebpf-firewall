//go:build linux

// Package sandbox runs a command in a short-lived, resource-limited cgroup v2
// with its own PID/IPC/UTS/mount namespaces and a throwaway tmpfs workspace.
// Everything it creates is torn down when the sandbox ends.
package sandbox

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// CgroupRoot is where sandbox cgroups are created.
const CgroupRoot = "/sys/fs/cgroup/sbx"

// Config describes one sandbox.
type Config struct {
	ID        string
	Command   []string
	Env       []string
	MemoryMax string  // e.g. "512M"; empty = unlimited
	PidsMax   int     // 0 = unlimited
	CPUs      float64 // 0 = unlimited; 0.5 = half a core
	TmpfsSize string  // e.g. "256m"
	UID, GID  int     // -1 = inherit
}

// Sandbox is a created but not necessarily running sandbox.
type Sandbox struct {
	cfg        Config
	CgroupPath string
	Workdir    string
	cgDir      *os.File
	mounted    bool
}

// Usage is resource usage reported by the cgroup.
type Usage struct {
	CPUUsec      uint64 `json:"cpu_usec"`
	MemPeakBytes uint64 `json:"mem_peak_bytes,omitempty"`
}

// New creates the cgroup and workspace. Call Cleanup when done, even on error.
func New(cfg Config) (*Sandbox, error) {
	var st unix.Statfs_t
	if err := unix.Statfs("/sys/fs/cgroup", &st); err != nil {
		return nil, fmt.Errorf("statfs /sys/fs/cgroup: %w", err)
	}
	if st.Type != unix.CGROUP2_SUPER_MAGIC {
		return nil, errors.New("cgroup v2 (unified hierarchy) is required at /sys/fs/cgroup")
	}

	if err := os.MkdirAll(CgroupRoot, 0o755); err != nil {
		return nil, fmt.Errorf("create %s: %w", CgroupRoot, err)
	}
	// Best effort: controllers may already be enabled or delegated elsewhere.
	_ = enableControllers("/sys/fs/cgroup")
	_ = enableControllers(CgroupRoot)

	s := &Sandbox{cfg: cfg, CgroupPath: filepath.Join(CgroupRoot, cfg.ID)}
	if err := os.Mkdir(s.CgroupPath, 0o755); err != nil {
		return nil, fmt.Errorf("create cgroup: %w", err)
	}
	if err := s.applyLimits(); err != nil {
		return s, err
	}

	dir, err := os.MkdirTemp("", "sbx-"+cfg.ID+"-")
	if err != nil {
		return s, fmt.Errorf("create workdir: %w", err)
	}
	s.Workdir = dir
	size := cfg.TmpfsSize
	if size == "" {
		size = "256m"
	}
	if err := unix.Mount("tmpfs", dir, "tmpfs", unix.MS_NOSUID|unix.MS_NODEV, "size="+size+",mode=0700"); err != nil {
		return s, fmt.Errorf("mount tmpfs workspace: %w", err)
	}
	s.mounted = true
	if cfg.UID >= 0 {
		if err := os.Chown(dir, cfg.UID, cfg.GID); err != nil {
			return s, fmt.Errorf("chown workspace: %w", err)
		}
	}

	f, err := os.Open(s.CgroupPath)
	if err != nil {
		return s, fmt.Errorf("open cgroup: %w", err)
	}
	s.cgDir = f
	return s, nil
}

func enableControllers(dir string) error {
	return os.WriteFile(filepath.Join(dir, "cgroup.subtree_control"), []byte("+cpu +memory +pids"), 0o644)
}

func (s *Sandbox) applyLimits() error {
	write := func(file, val string) error {
		if err := os.WriteFile(filepath.Join(s.CgroupPath, file), []byte(val), 0o644); err != nil {
			return fmt.Errorf("set %s=%s: %w", file, val, err)
		}
		return nil
	}
	if s.cfg.MemoryMax != "" {
		if err := write("memory.max", s.cfg.MemoryMax); err != nil {
			return err
		}
		_ = write("memory.swap.max", "0") // absent when swap accounting is off
	}
	if s.cfg.PidsMax > 0 {
		if err := write("pids.max", strconv.Itoa(s.cfg.PidsMax)); err != nil {
			return err
		}
	}
	if s.cfg.CPUs > 0 {
		const period = 100000
		quota := int(s.cfg.CPUs * period)
		if quota < 1000 {
			quota = 1000
		}
		if err := write("cpu.max", fmt.Sprintf("%d %d", quota, period)); err != nil {
			return err
		}
	}
	return nil
}

// Command builds the process. It starts directly inside the sandbox cgroup
// (clone3 CLONE_INTO_CGROUP), so the firewall applies from its first syscall.
func (s *Sandbox) Command() *exec.Cmd {
	cmd := exec.Command(s.cfg.Command[0], s.cfg.Command[1:]...)
	cmd.Dir = s.Workdir
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.Env = append([]string{
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"HOME=" + s.Workdir,
		"TMPDIR=" + s.Workdir,
		"SBX_ID=" + s.cfg.ID,
		"TERM=" + os.Getenv("TERM"),
	}, s.cfg.Env...)
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags:  syscall.CLONE_NEWPID | syscall.CLONE_NEWNS | syscall.CLONE_NEWUTS | syscall.CLONE_NEWIPC,
		UseCgroupFD: true,
		CgroupFD:    int(s.cgDir.Fd()),
		Pdeathsig:   syscall.SIGKILL,
	}
	if s.cfg.UID >= 0 {
		cmd.SysProcAttr.Credential = &syscall.Credential{
			Uid:         uint32(s.cfg.UID),
			Gid:         uint32(s.cfg.GID),
			NoSetGroups: true,
		}
	}
	return cmd
}

// Kill terminates every process in the sandbox, including any that escaped
// the main process's process tree.
func (s *Sandbox) Kill() error {
	err := os.WriteFile(filepath.Join(s.CgroupPath, "cgroup.kill"), []byte("1"), 0o644)
	if err == nil {
		return nil
	}
	// Kernels before 5.14 have no cgroup.kill.
	pids, perr := s.pids()
	if perr != nil {
		return errors.Join(err, perr)
	}
	for _, pid := range pids {
		_ = unix.Kill(pid, unix.SIGKILL)
	}
	return nil
}

func (s *Sandbox) pids() ([]int, error) {
	f, err := os.Open(filepath.Join(s.CgroupPath, "cgroup.procs"))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var pids []int
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if pid, err := strconv.Atoi(strings.TrimSpace(sc.Text())); err == nil {
			pids = append(pids, pid)
		}
	}
	return pids, sc.Err()
}

// Usage reads cumulative CPU time and peak memory. Call before Cleanup.
func (s *Sandbox) Usage() Usage {
	var u Usage
	if b, err := os.ReadFile(filepath.Join(s.CgroupPath, "cpu.stat")); err == nil {
		for _, line := range strings.Split(string(b), "\n") {
			if v, ok := strings.CutPrefix(line, "usage_usec "); ok {
				u.CPUUsec, _ = strconv.ParseUint(strings.TrimSpace(v), 10, 64)
			}
		}
	}
	if b, err := os.ReadFile(filepath.Join(s.CgroupPath, "memory.peak")); err == nil {
		u.MemPeakBytes, _ = strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
	}
	return u
}

// Cleanup kills anything left, removes the cgroup and destroys the workspace.
// It is safe to call on a partially created sandbox.
func (s *Sandbox) Cleanup() error {
	var errs []error
	if s.cgDir != nil {
		errs = append(errs, s.cgDir.Close())
	}
	if _, err := os.Stat(s.CgroupPath); err == nil {
		_ = s.Kill()
		deadline := time.Now().Add(5 * time.Second)
		for {
			pids, err := s.pids()
			if err != nil || len(pids) == 0 {
				break
			}
			if time.Now().After(deadline) {
				errs = append(errs, fmt.Errorf("cgroup still has %d processes", len(pids)))
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
		if err := os.Remove(s.CgroupPath); err != nil {
			errs = append(errs, fmt.Errorf("remove cgroup: %w", err))
		}
	}
	if s.mounted {
		if err := unix.Unmount(s.Workdir, unix.MNT_DETACH); err != nil {
			errs = append(errs, fmt.Errorf("unmount workspace: %w", err))
		}
	}
	if s.Workdir != "" {
		errs = append(errs, os.RemoveAll(s.Workdir))
	}
	return errors.Join(errs...)
}
