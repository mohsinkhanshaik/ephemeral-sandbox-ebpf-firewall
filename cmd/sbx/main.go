//go:build linux

// Command sbx runs a command in an ephemeral sandbox with an eBPF egress
// firewall.
//
//	sudo sbx run --allow 1.1.1.1:443 --allow-dns --ttl 5m -- curl https://1.1.1.1
package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/mohsinkhanshaik/ephemeral-sandbox-ebpf-firewall/internal/firewall"
	"github.com/mohsinkhanshaik/ephemeral-sandbox-ebpf-firewall/internal/policy"
	"github.com/mohsinkhanshaik/ephemeral-sandbox-ebpf-firewall/internal/sandbox"
)

var version = "dev"

const usage = `sbx - ephemeral sandboxes with an eBPF egress firewall

Usage:
  sbx run [flags] -- <command> [args...]   run a command in a new sandbox
  sbx check                                check kernel and cgroup support
  sbx version

Run "sbx run -h" for run flags.
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	switch os.Args[1] {
	case "run":
		os.Exit(run(os.Args[2:]))
	case "check":
		os.Exit(check())
	case "version":
		fmt.Println(version)
	case "-h", "--help", "help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n%s", os.Args[1], usage)
		os.Exit(2)
	}
}

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

type summary struct {
	Sandbox  string `json:"sandbox"`
	ExitCode int    `json:"exit_code"`
	Reason   string `json:"reason"`
	Duration string `json:"duration"`
	firewall.Stats
	sandbox.Usage
}

func run(args []string) int {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	var allows multiFlag
	fs.Var(&allows, "allow", "allow egress to `ADDR[/BITS][:PORT]` or HOST:PORT (repeatable)")
	allowDNS := fs.Bool("allow-dns", false, "allow port 53 to the nameservers in /etc/resolv.conf")
	allowICMP := fs.Bool("allow-icmp", false, "allow ICMP to hosts that are allowed on all ports")
	noLoopback := fs.Bool("no-loopback", false, "also block 127.0.0.0/8 and ::1")
	logAllowed := fs.Bool("log-allowed", false, "log allowed connections, not just denied ones")
	ttl := fs.Duration("ttl", 15*time.Minute, "kill the sandbox after this long")
	mem := fs.String("memory", "512M", "memory limit (cgroup memory.max), empty for none")
	pids := fs.Int("pids", 256, "max processes/threads, 0 for none")
	cpus := fs.Float64("cpus", 1, "CPU limit in cores, 0 for none")
	tmpfs := fs.String("workspace-size", "256m", "size of the tmpfs workspace")
	userSpec := fs.String("user", "nobody", "run as `USER[:GROUP]` or UID[:GID]; \"root\" to keep root")
	var envs multiFlag
	fs.Var(&envs, "env", "set `KEY=VALUE` in the sandbox (repeatable)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	command := fs.Args()
	if len(command) == 0 {
		fmt.Fprintln(os.Stderr, "sbx run: missing command (use -- <command> [args...])")
		return 2
	}

	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	fail := func(msg string, err error) int {
		log.Error(msg, "err", err)
		return 125
	}

	if os.Geteuid() != 0 {
		return fail("sbx must run as root", errors.New("needs CAP_SYS_ADMIN and CAP_BPF to manage cgroups and attach eBPF"))
	}

	var rules []policy.Rule
	for _, a := range allows {
		r, err := policy.Parse(a, policy.SystemResolver)
		if err != nil {
			return fail("invalid --allow", err)
		}
		rules = append(rules, r...)
	}
	if *allowDNS {
		f, err := os.Open("/etc/resolv.conf")
		if err != nil {
			return fail("read resolv.conf", err)
		}
		r, err := policy.ParseResolvConf(f)
		f.Close()
		if err != nil {
			return fail("parse resolv.conf", err)
		}
		rules = append(rules, r...)
	}

	uid, gid, err := lookupUser(*userSpec)
	if err != nil {
		return fail("invalid --user", err)
	}

	id := newID()
	start := time.Now()
	sb, err := sandbox.New(sandbox.Config{
		ID:        id,
		Command:   command,
		Env:       envs,
		MemoryMax: *mem,
		PidsMax:   *pids,
		CPUs:      *cpus,
		TmpfsSize: *tmpfs,
		UID:       uid,
		GID:       gid,
	})
	if sb != nil {
		defer func() {
			if err := sb.Cleanup(); err != nil {
				log.Warn("cleanup incomplete", "sandbox", id, "err", err)
			}
		}()
	}
	if err != nil {
		return fail("create sandbox", err)
	}

	fw, err := firewall.Load(firewall.Options{
		CgroupPath:    sb.CgroupPath,
		Rules:         rules,
		AllowICMP:     *allowICMP,
		AllowLoopback: !*noLoopback,
		LogAllowed:    *logAllowed,
	})
	if err != nil {
		return fail("load firewall", err)
	}
	defer fw.Close()

	ruleStrs := make([]string, len(rules))
	for i, r := range rules {
		ruleStrs[i] = r.String()
	}
	log.Info("sandbox starting", "sandbox", id, "command", command, "allow", ruleStrs, "ttl", ttl.String())

	go func() {
		_ = fw.Run(func(e firewall.Event) {
			log.Info("egress", "sandbox", id, "verdict", e.Verdict, "hook", e.Hook, "proto", e.Proto, "dst", e.Dst)
		})
	}()

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(sigs)

	cmd := sb.Command()
	if err := cmd.Start(); err != nil {
		return fail("start command", err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	timer := time.NewTimer(*ttl)
	defer timer.Stop()

	reason := "exited"
	var waitErr error
	select {
	case waitErr = <-done:
	case <-timer.C:
		reason = "ttl_expired"
		_ = sb.Kill()
		waitErr = <-done
	case s := <-sigs:
		reason = "signal_" + s.String()
		_ = sb.Kill()
		waitErr = <-done
	}

	code := exitCode(waitErr)
	switch reason {
	case "ttl_expired":
		code = 124 // same convention as timeout(1)
	case "exited":
	default:
		code = 130
	}

	stats, _ := fw.Stats()
	out, _ := json.Marshal(summary{
		Sandbox:  id,
		ExitCode: code,
		Reason:   reason,
		Duration: time.Since(start).Round(time.Millisecond).String(),
		Stats:    stats,
		Usage:    sb.Usage(),
	})
	fmt.Fprintln(os.Stderr, string(out))
	return code
}

func exitCode(err error) int {
	if err == nil {
		return 0
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		if ws, ok := ee.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			return 128 + int(ws.Signal())
		}
		return ee.ExitCode()
	}
	return 125
}

func lookupUser(spec string) (int, int, error) {
	if spec == "" || spec == "root" {
		return -1, -1, nil
	}
	name, group, _ := strings.Cut(spec, ":")

	uid, err := strconv.Atoi(name)
	gid := uid
	if err != nil {
		u, err := user.Lookup(name)
		if err != nil {
			return 0, 0, err
		}
		uid, _ = strconv.Atoi(u.Uid)
		gid, _ = strconv.Atoi(u.Gid)
	}
	if group != "" {
		if g, err := strconv.Atoi(group); err == nil {
			gid = g
		} else {
			grp, err := user.LookupGroup(group)
			if err != nil {
				return 0, 0, err
			}
			gid, _ = strconv.Atoi(grp.Gid)
		}
	}
	return uid, gid, nil
}

func newID() string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func check() int {
	ok := true
	report := func(name string, err error) {
		if err != nil {
			ok = false
			fmt.Printf("FAIL  %-22s %v\n", name, err)
			return
		}
		fmt.Printf("ok    %s\n", name)
	}

	if os.Geteuid() != 0 {
		report("root", errors.New("run as root"))
	} else {
		report("root", nil)
	}
	_, err := os.Stat("/sys/fs/cgroup/cgroup.controllers")
	report("cgroup v2", err)
	_, err = os.Stat("/sys/kernel/btf/vmlinux")
	report("kernel BTF", err)
	report("load eBPF programs", firewall.Probe())

	if !ok {
		return 1
	}
	return 0
}
