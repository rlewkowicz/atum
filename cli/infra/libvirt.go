package infra

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"atum/cli/process"

	"golang.org/x/sys/unix"
)

const (
	libvirtRulePath      = "/etc/polkit-1/rules.d/49-atum-libvirt-all-users.rules"
	forwardingStateDir   = "/etc/atum"
	forwardingStatePath  = forwardingStateDir + "/libvirt-forwarding.bridge"
	libvirtACLStatePath  = forwardingStateDir + "/libvirt-qemu-search.acl"
	bridgeStateLimit     = 16
	libvirtACLStateLimit = 64 << 10
	libvirtURI           = "qemu:///system"
	libvirtNetwork       = "atum"
	libvirtRule          = `// WARNING: system libvirt management is effectively root-equivalent host access.
polkit.addRule(function(action, subject) {
    if (action.id == "org.libvirt.unix.manage") {
        return polkit.Result.YES;
    }
});
`
)

var bridgePattern = regexp.MustCompile(`^[[:alnum:]_.:-]{1,15}$`)

type forwardingAction uint8

const (
	invalidForwardingAction forwardingAction = iota
	installForwarding
	statusForwarding
	uninstallForwarding
)

type ForwardingPlan struct {
	action      forwardingAction
	savedBridge string
	discover    bool
}

func PlanForwarding(action string) (ForwardingPlan, error) {
	var selected forwardingAction
	switch action {
	case "install":
		selected = installForwarding
	case "status":
		selected = statusForwarding
	case "uninstall":
		selected = uninstallForwarding
	default:
		return ForwardingPlan{}, fmt.Errorf("unsupported libvirt forwarding action %q", action)
	}
	bridge, exists, err := readForwardingState()
	if err != nil {
		return ForwardingPlan{}, err
	}
	return ForwardingPlan{
		action: selected, savedBridge: bridge,
		discover: selected == installForwarding || !exists,
	}, nil
}

func (plan ForwardingPlan) Valid() bool {
	switch plan.action {
	case installForwarding:
		return plan.discover
	case statusForwarding, uninstallForwarding:
		return plan.discover == (plan.savedBridge == "")
	default:
		return false
	}
}

func (plan ForwardingPlan) RequiresVirsh() bool {
	return plan.Valid() && plan.discover
}

func (action forwardingAction) name() string {
	switch action {
	case installForwarding:
		return "install"
	case statusForwarding:
		return "status"
	case uninstallForwarding:
		return "uninstall"
	default:
		return "invalid"
	}
}

type LibvirtService struct {
	Runner        process.Runner
	OutputRunner  process.OutputRunner
	Out           io.Writer
	EUID          int
	VirshBin      string
	FirewallBin   string
	RestoreconBin string
	GetfaclBin    string
	SetfaclBin    string
	ProjectRoot   string
}

func (service LibvirtService) Permissions(ctx context.Context, action string) error {
	if service.Runner == nil {
		return errors.New("libvirt command runner is unavailable")
	}
	switch action {
	case "install":
		if err := service.requireRoot(action); err != nil {
			return err
		}
		if err := atomicHostFile(libvirtRulePath, []byte(libvirtRule), 0o644); err != nil {
			return err
		}
		if service.RestoreconBin != "" {
			if err := service.Runner.Run(ctx, process.Command{Name: service.RestoreconBin, Args: []string{libvirtRulePath}}); err != nil {
				return fmt.Errorf("restore libvirt policy context: %w", err)
			}
		}
		if err := service.installQEMUSearchACL(ctx); err != nil {
			return err
		}
		return service.print("installed %s\nall local users may now manage %s without authentication\n", libvirtRulePath, libvirtURI)
	case "status":
		_, found, err := readManagedHostFile(libvirtRulePath, 16<<10, 0o644)
		if err != nil {
			return err
		}
		if !found {
			return fmt.Errorf("not installed: %s", libvirtRulePath)
		}
		if err := service.validateQEMUSearchACLState(); err != nil {
			return err
		}
		return service.print("installed: %s\n", libvirtRulePath)
	case "uninstall":
		if err := service.requireRoot(action); err != nil {
			return err
		}
		if err := service.restoreQEMUSearchACL(ctx); err != nil {
			return err
		}
		if err := removeHostFile(libvirtRulePath, 0o644); err != nil {
			return err
		}
		return service.print("removed %s\n", libvirtRulePath)
	default:
		return fmt.Errorf("unsupported libvirt permissions action %q", action)
	}
}

func (service LibvirtService) installQEMUSearchACL(ctx context.Context) error {
	directories, err := restrictedProjectAncestors(service.ProjectRoot)
	if err != nil {
		return err
	}
	if len(directories) == 0 {
		return nil
	}
	account, err := qemuAccount()
	if err != nil {
		return err
	}
	state, found, err := readManagedHostFile(libvirtACLStatePath, libvirtACLStateLimit, 0o600)
	if err != nil {
		return err
	}
	header := libvirtACLStateHeader(service.ProjectRoot)
	if found {
		if !bytes.HasPrefix(state, header) {
			return fmt.Errorf("managed libvirt ACL state belongs to a different project root")
		}
	} else {
		if service.OutputRunner == nil || service.GetfaclBin == "" {
			return errors.New("validated getfacl identity is required")
		}
		arguments := make([]string, 0, len(directories)+2)
		arguments = append(arguments, "--absolute-names", "--numeric")
		arguments = append(arguments, directories...)
		snapshot, err := service.OutputRunner.Output(ctx, process.Command{
			Name: service.GetfaclBin,
			Args: arguments,
		})
		if err != nil {
			return fmt.Errorf("snapshot project ancestor ACLs: %w", err)
		}
		state = make([]byte, 0, len(header)+len(snapshot))
		state = append(state, header...)
		state = append(state, snapshot...)
		if err := atomicHostFile(libvirtACLStatePath, state, 0o600); err != nil {
			clear(state)
			return fmt.Errorf("store project ancestor ACL snapshot: %w", err)
		}
		clear(state)
	}
	if service.SetfaclBin == "" {
		return errors.New("validated setfacl identity is required")
	}
	arguments := make([]string, 0, len(directories)+3)
	arguments = append(arguments, "--modify", "user:"+account.Uid+":--x", "--")
	arguments = append(arguments, directories...)
	if err := service.Runner.Run(ctx, process.Command{
		Name: service.SetfaclBin,
		Args: arguments,
	}); err != nil {
		return fmt.Errorf("grant QEMU project search access: %w", err)
	}
	return nil
}

func (service LibvirtService) validateQEMUSearchACLState() error {
	directories, err := restrictedProjectAncestors(service.ProjectRoot)
	if err != nil || len(directories) == 0 {
		return err
	}
	state, found, err := readManagedHostFile(libvirtACLStatePath, libvirtACLStateLimit, 0o600)
	if err != nil {
		return err
	}
	if !found || !bytes.HasPrefix(state, libvirtACLStateHeader(service.ProjectRoot)) {
		return errors.New("QEMU project search ACL is not installed")
	}
	return nil
}

func (service LibvirtService) restoreQEMUSearchACL(ctx context.Context) error {
	state, found, err := readManagedHostFile(libvirtACLStatePath, libvirtACLStateLimit, 0o600)
	if err != nil || !found {
		return err
	}
	if !bytes.HasPrefix(state, libvirtACLStateHeader(service.ProjectRoot)) {
		return errors.New("managed libvirt ACL state belongs to a different project root")
	}
	if service.SetfaclBin == "" {
		return errors.New("validated setfacl identity is required")
	}
	if err := service.Runner.Run(ctx, process.Command{
		Name: service.SetfaclBin,
		Args: []string{"--restore=" + libvirtACLStatePath},
	}); err != nil {
		return fmt.Errorf("restore project ancestor ACLs: %w", err)
	}
	return removeHostFile(libvirtACLStatePath, 0o600)
}

func libvirtACLStateHeader(projectRoot string) []byte {
	digest := sha256.Sum256([]byte(filepath.Clean(projectRoot)))
	return []byte("# atum-project-root-sha256: " + hex.EncodeToString(digest[:]) + "\n")
}

func restrictedProjectAncestors(projectRoot string) ([]string, error) {
	if !filepath.IsAbs(projectRoot) || filepath.Clean(projectRoot) != projectRoot {
		return nil, fmt.Errorf("project root %q must be clean and absolute", projectRoot)
	}
	directories := make([]string, 0, 8)
	for current := projectRoot; current != string(filepath.Separator); current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil {
			return nil, fmt.Errorf("inspect project ancestor %s: %w", current, err)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return nil, fmt.Errorf("project ancestor %s must be a real directory", current)
		}
		if info.Mode().Perm()&0o001 == 0 {
			directories = append(directories, current)
		}
	}
	slices.Reverse(directories)
	return directories, nil
}

func qemuAccount() (*user.User, error) {
	for _, name := range []string{"qemu", "libvirt-qemu"} {
		account, err := user.Lookup(name)
		if err == nil {
			return account, nil
		}
		var unknown user.UnknownUserError
		if !errors.As(err, &unknown) {
			return nil, fmt.Errorf("resolve QEMU account %s: %w", name, err)
		}
	}
	return nil, errors.New("resolve QEMU account: neither qemu nor libvirt-qemu exists")
}

func (service LibvirtService) Forwarding(ctx context.Context, plan ForwardingPlan) error {
	if service.Runner == nil {
		return errors.New("libvirt command runner is unavailable")
	}
	if !plan.Valid() {
		return errors.New("valid libvirt forwarding plan is required")
	}
	if service.FirewallBin == "" {
		return errors.New("validated firewalld preflight identity is required")
	}
	action := plan.action.name()
	if err := service.requireRoot("forwarding " + action); err != nil {
		return err
	}
	if err := service.Runner.Run(ctx, process.Command{Name: service.FirewallBin, Args: []string{"--state"}}); err != nil {
		return errors.New("firewalld must be running to manage persistent forwarding rules")
	}
	bridge := plan.savedBridge
	if plan.discover {
		var err error
		bridge, err = service.discoverBridge(ctx)
		if err != nil {
			return err
		}
	}
	if plan.action == installForwarding && plan.savedBridge != "" && plan.savedBridge != bridge {
		if err := service.removeForwardingRules(ctx, plan.savedBridge); err != nil {
			return err
		}
	}
	for _, permanent := range []bool{true, false} {
		for _, direction := range []string{"ingress", "return"} {
			exists, err := service.forwardingRule(ctx, "query", permanent, bridge, direction)
			if err != nil {
				return err
			}
			switch plan.action {
			case installForwarding:
				if !exists {
					if _, err := service.forwardingRule(ctx, "add", permanent, bridge, direction); err != nil {
						return err
					}
				}
			case statusForwarding:
				if !exists {
					return fmt.Errorf("missing forwarding rule for bridge %s", bridge)
				}
			case uninstallForwarding:
				if exists {
					if _, err := service.forwardingRule(ctx, "remove", permanent, bridge, direction); err != nil {
						return err
					}
				}
			}
		}
	}
	switch plan.action {
	case installForwarding:
		if err := atomicHostFile(forwardingStatePath, []byte(bridge+"\n"), 0o644); err != nil {
			return err
		}
		return service.print("installed persistent Docker forwarding exceptions for %s (%s)\n", libvirtNetwork, bridge)
	case statusForwarding:
		return service.print("installed: persistent Docker forwarding exceptions for %s (%s)\n", libvirtNetwork, bridge)
	case uninstallForwarding:
		if err := removeHostFile(forwardingStatePath, 0o644); err != nil {
			return err
		}
		return service.print("removed Docker forwarding exceptions for %s (%s)\n", libvirtNetwork, bridge)
	default:
		return errors.New("valid libvirt forwarding plan is required")
	}
}

func (service LibvirtService) discoverBridge(ctx context.Context) (string, error) {
	if service.OutputRunner == nil {
		return "", errors.New("libvirt bridge discovery requires output capture")
	}
	if service.VirshBin == "" {
		return "", errors.New("validated virsh preflight identity is required for live bridge discovery")
	}
	output, err := service.OutputRunner.Output(ctx, process.Command{
		Name: service.VirshBin,
		Args: []string{"-c", libvirtURI, "net-info", libvirtNetwork},
	})
	if err != nil {
		return "", fmt.Errorf("inspect libvirt network %s: %w", libvirtNetwork, err)
	}
	for _, line := range strings.Split(string(output), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "Bridge:" && bridgePattern.MatchString(fields[1]) {
			return fields[1], nil
		}
	}
	return "", fmt.Errorf("libvirt network %s has no valid bridge", libvirtNetwork)
}

func (service LibvirtService) forwardingRule(ctx context.Context, action string, permanent bool, bridge, direction string) (bool, error) {
	args := make([]string, 0, 16)
	args = append(args, "--quiet")
	if permanent {
		args = append(args, "--permanent")
	}
	args = append(args, "--direct", "--"+action+"-rule", "ipv4", "filter", "DOCKER-USER", "0")
	if direction == "ingress" {
		args = append(args, "-i", bridge, "-j", "ACCEPT")
	} else {
		args = append(args, "-o", bridge, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT")
	}
	err := service.Runner.Run(ctx, process.Command{Name: service.FirewallBin, Args: args})
	if action == "query" {
		if err == nil {
			return true, nil
		}
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) && exitErr.ExitCode() == 1 {
			return false, nil
		}
		return false, fmt.Errorf("query firewalld rule for bridge %s: %w", bridge, err)
	}
	if err != nil {
		return false, fmt.Errorf("firewalld %s failed for bridge %s: %w", action, bridge, err)
	}
	return true, nil
}

func (service LibvirtService) removeForwardingRules(ctx context.Context, bridge string) error {
	for _, permanent := range []bool{true, false} {
		for _, direction := range []string{"ingress", "return"} {
			exists, err := service.forwardingRule(ctx, "query", permanent, bridge, direction)
			if err != nil {
				return err
			}
			if exists {
				if _, err := service.forwardingRule(ctx, "remove", permanent, bridge, direction); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func (service LibvirtService) requireRoot(action string) error {
	if service.EUID != 0 {
		return fmt.Errorf("libvirt %s requires root; rerun with sudo", action)
	}
	return nil
}

func (service LibvirtService) print(format string, args ...any) error {
	if service.Out == nil {
		return nil
	}
	_, err := fmt.Fprintf(service.Out, format, args...)
	return err
}

func readForwardingState() (string, bool, error) {
	data, exists, err := readManagedHostFile(forwardingStatePath, bridgeStateLimit, 0o644)
	if err != nil {
		return "", false, err
	}
	if !exists {
		return "", false, nil
	}
	bridge := strings.TrimSuffix(string(data), "\n")
	if !bridgePattern.MatchString(bridge) || strings.Contains(bridge, "\n") {
		return "", false, fmt.Errorf("invalid forwarding bridge state in %s", forwardingStatePath)
	}
	return bridge, true, nil
}

func atomicHostFile(path string, data []byte, mode os.FileMode) error {
	directory := filepath.Dir(path)
	if directory == forwardingStateDir {
		if err := ensureRootDirectory(directory, 0o755, true); err != nil {
			return err
		}
	}
	directoryFD, err := secureHostDirectoryFD(directory)
	if err != nil {
		return err
	}
	defer unix.Close(directoryFD)
	name := filepath.Base(path)
	var existing unix.Stat_t
	if err := unix.Fstatat(directoryFD, name, &existing, unix.AT_SYMLINK_NOFOLLOW); err == nil {
		if !managedHostStat(existing, mode) {
			return fmt.Errorf("host path %s is not an exact managed regular file", path)
		}
	} else if !errors.Is(err, unix.ENOENT) {
		return err
	}
	temporaryName, temporaryFD, err := createHostTemporary(directoryFD, mode)
	if err != nil {
		return err
	}
	temporary := os.NewFile(uintptr(temporaryFD), filepath.Join(directory, temporaryName))
	if temporary == nil {
		_ = unix.Close(temporaryFD)
		_ = unix.Unlinkat(directoryFD, temporaryName, 0)
		return errors.New("create host temporary file")
	}
	published := false
	defer func() {
		if !published {
			_ = unix.Unlinkat(directoryFD, temporaryName, 0)
		}
	}()
	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := unix.Renameat(directoryFD, temporaryName, directoryFD, name); err != nil {
		return err
	}
	published = true
	if err := unix.Fsync(directoryFD); err != nil {
		return fmt.Errorf("sync host directory %s: %w", directory, err)
	}
	return nil
}

func removeHostFile(path string, mode os.FileMode) error {
	directory := filepath.Dir(path)
	directoryFD, err := secureHostDirectoryFD(directory)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer unix.Close(directoryFD)
	name := filepath.Base(path)
	var info unix.Stat_t
	if err := unix.Fstatat(directoryFD, name, &info, unix.AT_SYMLINK_NOFOLLOW); errors.Is(err, unix.ENOENT) {
		return nil
	} else if err != nil {
		return err
	}
	if !managedHostStat(info, mode) {
		return fmt.Errorf("refusing to remove non-managed host path %s", path)
	}
	if err := unix.Unlinkat(directoryFD, name, 0); err != nil {
		return err
	}
	if err := unix.Fsync(directoryFD); err != nil {
		return fmt.Errorf("sync host directory %s: %w", directory, err)
	}
	return nil
}

func ensureRootDirectory(path string, mode os.FileMode, create bool) error {
	if descriptor, err := secureHostDirectoryFD(path); err == nil {
		return unix.Close(descriptor)
	} else if !create || !errors.Is(err, os.ErrNotExist) {
		return err
	}
	parent := filepath.Dir(path)
	parentFD, err := secureHostDirectoryFD(parent)
	if err != nil {
		return err
	}
	defer unix.Close(parentFD)
	if err := unix.Mkdirat(parentFD, filepath.Base(path), uint32(mode.Perm())); err != nil &&
		!errors.Is(err, unix.EEXIST) {
		return fmt.Errorf("create host directory %s: %w", path, err)
	}
	if err := unix.Fsync(parentFD); err != nil {
		return fmt.Errorf("sync host parent directory %s: %w", parent, err)
	}
	descriptor, err := openSecureDirectoryAt(parentFD, filepath.Base(path), path)
	if err != nil {
		return err
	}
	return unix.Close(descriptor)
}

func secureHostDirectoryFD(path string) (int, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return -1, fmt.Errorf("host directory path %q must be clean and absolute", path)
	}
	descriptor, err := unix.Open(
		"/", unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY|unix.O_NOFOLLOW, 0)
	if err != nil {
		return -1, err
	}
	if err := validateSecureDirectoryFD(descriptor, "/"); err != nil {
		_ = unix.Close(descriptor)
		return -1, err
	}
	if path == "/" {
		return descriptor, nil
	}
	currentPath := ""
	for _, component := range strings.Split(strings.TrimPrefix(path, "/"), "/") {
		if component == "" || component == "." || component == ".." {
			_ = unix.Close(descriptor)
			return -1, fmt.Errorf("host directory path %q has an unsafe component", path)
		}
		currentPath += "/" + component
		next, openErr := openSecureDirectoryAt(descriptor, component, currentPath)
		_ = unix.Close(descriptor)
		if openErr != nil {
			return -1, openErr
		}
		descriptor = next
	}
	return descriptor, nil
}

func openSecureDirectoryAt(parent int, name, displayPath string) (int, error) {
	descriptor, err := unix.Openat(
		parent, name,
		unix.O_RDONLY|unix.O_CLOEXEC|unix.O_DIRECTORY|unix.O_NOFOLLOW,
		0,
	)
	if err != nil {
		return -1, err
	}
	if err := validateSecureDirectoryFD(descriptor, displayPath); err != nil {
		_ = unix.Close(descriptor)
		return -1, err
	}
	return descriptor, nil
}

func validateSecureDirectoryFD(descriptor int, path string) error {
	var info unix.Stat_t
	if err := unix.Fstat(descriptor, &info); err != nil {
		return err
	}
	if info.Mode&unix.S_IFMT != unix.S_IFDIR || info.Uid != 0 || info.Mode&0o022 != 0 {
		return fmt.Errorf("host directory %s is not secure root-owned storage", path)
	}
	return nil
}

type hostFilePolicy struct {
	managedMode os.FileMode
}

type openedHostFile struct {
	file *os.File
	info unix.Stat_t
}

func readManagedHostFile(
	path string,
	limit int64,
	mode os.FileMode,
) ([]byte, bool, error) {
	return readHostFile(path, limit, hostFilePolicy{managedMode: mode})
}

func readSystemHostFile(path string, limit int64) ([]byte, bool, error) {
	return readHostFile(path, limit, hostFilePolicy{})
}

func readHostFile(
	path string,
	limit int64,
	policy hostFilePolicy,
) ([]byte, bool, error) {
	opened, found, err := openHostFile(path)
	if err != nil || !found {
		return nil, found, err
	}
	defer opened.file.Close()
	if !admitHostFile(opened.info, policy) ||
		opened.info.Size < 0 || opened.info.Size > limit {
		return nil, false, fmt.Errorf("host path %s is not a bounded secure regular file", path)
	}
	data, err := io.ReadAll(io.LimitReader(opened.file, limit+1))
	if err != nil {
		return nil, false, fmt.Errorf("read bounded host path %s: %w", path, err)
	}
	if int64(len(data)) > limit {
		clear(data)
		return nil, false, fmt.Errorf("host path %s exceeds %d bytes", path, limit)
	}
	return data, true, nil
}

func openHostFile(path string) (openedHostFile, bool, error) {
	descriptor, info, found, err := openHostDescriptor(
		path, unix.O_RDONLY|unix.O_NONBLOCK)
	if err != nil || !found {
		return openedHostFile{}, found, err
	}
	file := os.NewFile(uintptr(descriptor), path)
	if file == nil {
		_ = unix.Close(descriptor)
		return openedHostFile{}, false, fmt.Errorf("open host path %s", path)
	}
	return openedHostFile{file: file, info: info}, true, nil
}

func openHostDescriptor(
	path string,
	flags int,
) (int, unix.Stat_t, bool, error) {
	var info unix.Stat_t
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || filepath.Base(path) == "." {
		return -1, info, false,
			fmt.Errorf("host file path %q must be clean and absolute", path)
	}
	directory := filepath.Dir(path)
	directoryFD, err := secureHostDirectoryFD(directory)
	if errors.Is(err, os.ErrNotExist) {
		return -1, info, false, nil
	}
	if err != nil {
		return -1, info, false, err
	}
	defer unix.Close(directoryFD)
	descriptor, err := unix.Openat(
		directoryFD, filepath.Base(path),
		flags|unix.O_CLOEXEC|unix.O_NOFOLLOW,
		0,
	)
	if errors.Is(err, os.ErrNotExist) {
		return -1, info, false, nil
	}
	if err != nil {
		return -1, info, false, err
	}
	if err := unix.Fstat(descriptor, &info); err != nil {
		_ = unix.Close(descriptor)
		return -1, unix.Stat_t{}, false, err
	}
	return descriptor, info, true, nil
}

func admitHostFile(info unix.Stat_t, policy hostFilePolicy) bool {
	if info.Mode&unix.S_IFMT != unix.S_IFREG || info.Uid != 0 || info.Gid != 0 ||
		info.Mode&0o022 != 0 {
		return false
	}
	if policy.managedMode == 0 {
		return true
	}
	return managedHostStat(info, policy.managedMode)
}

func managedHostStat(info unix.Stat_t, mode os.FileMode) bool {
	expected := uint32(mode.Perm())
	if mode&os.ModeSetuid != 0 {
		expected |= unix.S_ISUID
	}
	if mode&os.ModeSetgid != 0 {
		expected |= unix.S_ISGID
	}
	if mode&os.ModeSticky != 0 {
		expected |= unix.S_ISVTX
	}
	const modeMask = uint32(0o777 | unix.S_ISUID | unix.S_ISGID | unix.S_ISVTX)
	return info.Mode&unix.S_IFMT == unix.S_IFREG &&
		info.Nlink == 1 && info.Uid == 0 && info.Gid == 0 &&
		info.Mode&modeMask == expected
}

func createHostTemporary(directoryFD int, mode os.FileMode) (string, int, error) {
	var random [12]byte
	for attempt := 0; attempt < 8; attempt++ {
		if _, err := rand.Read(random[:]); err != nil {
			return "", -1, err
		}
		name := ".atum-host-" + hex.EncodeToString(random[:])
		descriptor, err := unix.Openat(
			directoryFD,
			name,
			unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_CLOEXEC|unix.O_NOFOLLOW,
			uint32(mode.Perm()),
		)
		if errors.Is(err, unix.EEXIST) {
			continue
		}
		if err != nil {
			return "", -1, err
		}
		if err := unix.Fchmod(descriptor, uint32(mode.Perm())); err != nil {
			_ = unix.Close(descriptor)
			_ = unix.Unlinkat(directoryFD, name, 0)
			return "", -1, err
		}
		var info unix.Stat_t
		if err := unix.Fstat(descriptor, &info); err != nil || !managedHostStat(info, mode) {
			_ = unix.Close(descriptor)
			_ = unix.Unlinkat(directoryFD, name, 0)
			return "", -1, errors.New("host temporary file has unsafe ownership")
		}
		return name, descriptor, nil
	}
	return "", -1, errors.New("allocate unique host temporary file")
}
