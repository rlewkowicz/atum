package tui

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"atum/cli/process"
	"atum/cli/progress"
)

const (
	observedLineLimit     = 128 << 10
	observedResourceLimit = 512
)

var (
	ansiPattern            = regexp.MustCompile(`\x1b\[[0-?]*[ -/]*[@-~]`)
	terraformPlanPattern   = regexp.MustCompile(`^# (libvirt_(?:network|domain|volume|cloudinit_disk)\.[^ ]+) will be (?:created|destroyed)$`)
	terraformActionPattern = regexp.MustCompile(`^(libvirt_(?:network|domain|volume|cloudinit_disk)\.[^:]+): (Creating|Creation complete|Destroying|Destruction complete|Refreshing state)`)
)

type lineObserver struct {
	session *Session
	command process.Command
	buffer  []byte
	drop    bool
}

func (observer *lineObserver) Write(data []byte) (int, error) {
	consumed := 0
	for len(data) != 0 {
		newline := bytes.IndexByte(data, '\n')
		part := data
		if newline >= 0 {
			part = data[:newline]
		}
		if !observer.drop {
			remaining := observedLineLimit - len(observer.buffer)
			if len(part) <= remaining {
				observer.buffer = append(observer.buffer, part...)
			} else {
				observer.buffer = observer.buffer[:0]
				observer.drop = true
			}
		}
		consumed += len(part)
		data = data[len(part):]
		if newline < 0 {
			break
		}
		consumed++
		data = data[1:]
		observer.flush()
	}
	return consumed, nil
}

func (observer *lineObserver) Close() {
	if len(observer.buffer) != 0 && !observer.drop {
		observer.flush()
	}
	observer.buffer = nil
}

func (observer *lineObserver) flush() {
	if !observer.drop && len(observer.buffer) != 0 {
		observer.session.observeLine(observer.command, string(observer.buffer))
	}
	observer.buffer = observer.buffer[:0]
	observer.drop = false
}

type resourceSet struct {
	expected map[string]struct{}
	complete map[string]struct{}
	failed   map[string]struct{}
}

type terraformResourceIdentity struct {
	Address string `json:"addr"`
}

type terraformHook struct {
	Resource       terraformResourceIdentity `json:"resource"`
	Action         string                    `json:"action"`
	Output         string                    `json:"output"`
	ElapsedSeconds int                       `json:"elapsed_seconds"`
}

type terraformChange struct {
	Resource terraformResourceIdentity `json:"resource"`
	Action   string                    `json:"action"`
}

type terraformChanges struct {
	Add       int    `json:"add"`
	Change    int    `json:"change"`
	Remove    int    `json:"remove"`
	Operation string `json:"operation"`
}

type terraformEvent struct {
	Level   string           `json:"@level"`
	Message string           `json:"@message"`
	Module  string           `json:"@module"`
	Type    string           `json:"type"`
	UI      string           `json:"ui"`
	Hook    terraformHook    `json:"hook"`
	Change  terraformChange  `json:"change"`
	Changes terraformChanges `json:"changes"`
}

type outputParser struct {
	mu            sync.Mutex
	resources     map[string]*resourceSet
	seedActivity  bool
	activity      string
	activityTimer *time.Timer
	nodeStage     ansibleNodeStage
	activeNodes   map[string]struct{}
}

func newOutputParser() outputParser {
	return outputParser{
		resources:   make(map[string]*resourceSet, 6),
		activeNodes: make(map[string]struct{}, 8),
	}
}

type ansibleNodeStage uint8

const (
	ansibleNodeIdle ansibleNodeStage = iota
	ansibleNodeCordon
	ansibleNodeDrain
	ansibleNodeUpgrade
	ansibleNodeUncordon
)

func (parser *outputParser) observe(session *Session, command process.Command, raw string) {
	line := raw
	if ansiPattern.MatchString(line) {
		line = ansiPattern.ReplaceAllString(line, "")
	}
	line = strings.TrimSpace(line)
	if line == "" {
		return
	}
	parser.mu.Lock()
	defer parser.mu.Unlock()
	if ansibleCommand(command.Name) {
		activity := ansibleActivity(command)
		if detail, task := ansibleTaskDetail(line); task {
			parser.nodeStage = ansibleNodeStageFor(detail)
			parser.activity = line
			if parser.activityTimer == nil {
				parser.activityTimer = time.AfterFunc(200*time.Millisecond, func() {
					parser.emitActivity(session, activity)
				})
			}
			return
		}
		if detail, found := ansiblePullDetail(line); found {
			parser.activity = ""
			if parser.activityTimer != nil {
				parser.activityTimer.Stop()
				parser.activityTimer = nil
			}
			session.reportUnlocked(progress.Event{
				Phase: activity.Phase, ID: activity.ID, Label: activity.Label,
				Detail: detail, State: progress.Running,
			})
			return
		}
		parser.observeAnsibleResult(session, line)
		return
	}
	if !terraformCommand(command.Name) {
		return
	}
	if parser.observeTerraformEvent(session, command, line) {
		return
	}
	parser.observeSeedPlane(session, line)
	if line == "No changes. Your infrastructure matches the configuration." ||
		strings.HasPrefix(line, "Apply complete!") || strings.HasPrefix(line, "Destroy complete!") {
		session.reportUnlocked(progress.Event{
			Phase: progress.Infrastructure, ID: "*", State: progress.Complete, Detail: "converged",
		})
		return
	}
	if match := terraformPlanPattern.FindStringSubmatch(line); len(match) == 2 {
		parser.updateResource(session, match[1], progress.Running, "planned")
		return
	}
	if match := terraformActionPattern.FindStringSubmatch(line); len(match) == 3 {
		complete := match[2] == "Creation complete" || match[2] == "Destruction complete"
		state := progress.Running
		if complete {
			state = progress.Complete
		}
		parser.updateResource(session, match[1], state, strings.ToLower(match[2]))
	}
}

func terraformCommand(name string) bool {
	return name == "terraform" || strings.HasSuffix(name, "/terraform")
}

func (parser *outputParser) observeTerraformEvent(
	session *Session,
	command process.Command,
	line string,
) bool {
	if len(line) < 2 || line[0] != '{' {
		return false
	}
	var event terraformEvent
	if err := json.Unmarshal([]byte(line), &event); err != nil || event.Module != "terraform.ui" || event.Type == "" {
		return false
	}
	switch event.Type {
	case "version":
		if event.UI != "" && !strings.HasPrefix(event.UI, "1.") {
			session.reportUnlocked(progress.Event{
				Phase: progress.Infrastructure, ID: "terraform", Label: "Terraform",
				Detail: "Terraform JSON UI " + event.UI + "; retaining raw output", State: progress.Running,
			})
		}
	case "planned_change":
		parser.updateResource(session, event.Change.Resource.Address, progress.Running,
			terraformActionDetail(event.Change.Action, false))
	case "apply_start", "refresh_start":
		parser.updateResource(session, event.Hook.Resource.Address, progress.Running,
			terraformActionDetail(event.Hook.Action, false))
	case "provision_start":
		parser.updateResource(session, event.Hook.Resource.Address, progress.Running, "provisioning")
	case "apply_progress", "refresh_progress":
		detail := terraformActionDetail(event.Hook.Action, false)
		if event.Hook.ElapsedSeconds > 0 {
			detail += fmt.Sprintf(" · %ds", event.Hook.ElapsedSeconds)
		}
		parser.updateResource(session, event.Hook.Resource.Address, progress.Running, detail)
	case "apply_complete":
		parser.updateResource(session, event.Hook.Resource.Address, progress.Complete,
			terraformActionDetail(event.Hook.Action, true))
	case "refresh_complete":
		parser.updateResource(session, event.Hook.Resource.Address, progress.Running, "refreshed")
	case "provision_complete":
		parser.updateResource(session, event.Hook.Resource.Address, progress.Running, "provisioner complete")
	case "apply_errored", "refresh_errored", "provision_errored":
		parser.updateResource(session, event.Hook.Resource.Address, progress.Failed, "failed")
	case "provision_progress":
		if !parser.observeSeedPlane(session, event.Hook.Output) && event.Hook.Resource.Address != "" {
			parser.updateResource(session, event.Hook.Resource.Address, progress.Running, "provisioning")
		}
	case "change_summary":
		if event.Changes.Operation != "plan" || terraformOperation(command.Args) == "plan" {
			detail := fmt.Sprintf("%d added, %d changed, %d removed",
				event.Changes.Add, event.Changes.Change, event.Changes.Remove)
			session.reportUnlocked(progress.Event{
				Phase: progress.Infrastructure, ID: "*", Detail: detail, State: progress.Complete,
			})
		}
	case "init_output", "log":
		if event.Message != "" {
			session.reportUnlocked(progress.Event{
				Phase: progress.Infrastructure, ID: "terraform", Label: "Terraform",
				Detail: event.Message, State: progress.Running,
			})
		}
	case "diagnostic":
		if event.Message != "" {
			state := progress.Running
			if event.Level == "error" {
				state = progress.Failed
			}
			session.reportUnlocked(progress.Event{
				Phase: progress.Infrastructure, ID: "terraform", Label: "Terraform",
				Detail: event.Message, State: state,
			})
		}
	}
	return true
}

func terraformOperation(arguments []string) string {
	for _, argument := range arguments {
		if strings.HasPrefix(argument, "-") {
			continue
		}
		switch argument {
		case "apply", "destroy", "plan":
			return argument
		default:
			return ""
		}
	}
	return ""
}

func terraformActionDetail(action string, complete bool) string {
	if complete {
		switch action {
		case "create":
			return "created"
		case "delete":
			return "destroyed"
		case "read":
			return "refreshed"
		case "replace":
			return "replaced"
		case "update":
			return "updated"
		default:
			return "complete"
		}
	}
	switch action {
	case "create":
		return "creating"
	case "delete":
		return "destroying"
	case "read":
		return "refreshing"
	case "replace":
		return "replacing"
	case "update":
		return "updating"
	case "noop":
		return "unchanged"
	default:
		return "planned"
	}
}

func (parser *outputParser) observeSeedPlane(session *Session, line string) bool {
	const marker = "seed plane:"
	markerIndex := strings.Index(strings.ToLower(line), marker)
	if markerIndex < 0 {
		return false
	}
	detail := strings.TrimSpace(line[markerIndex+len(marker):])
	lower := strings.ToLower(detail)
	parser.seedActivity = true
	report := func(id, label, message string, state progress.State) {
		session.reportUnlocked(progress.Event{
			Phase: progress.Infrastructure, ID: id, Label: label, Detail: message, State: state,
		})
	}
	switch {
	case strings.HasPrefix(lower, "forgejo="):
		fields := strings.Fields(lower)
		forgejo, harbor := "waiting", "waiting"
		for _, field := range fields {
			key, value, found := strings.Cut(field, "=")
			if !found {
				continue
			}
			switch key {
			case "forgejo":
				forgejo = value
			case "harbor":
				harbor = value
			}
		}
		reportSeedService(report, "seed-forgejo", "Forgejo", forgejo)
		reportSeedService(report, "seed-harbor", "Seed Harbor", harbor)
	case strings.Contains(lower, "loading exact forgejo and harbor images"),
		strings.Contains(lower, "loaded exact forgejo and harbor images"):
		total := seedPlaneBytes(lower)
		current := int64(0)
		message := "loading exact seed images"
		if strings.Contains(lower, "loaded exact") {
			current = total
			message = "loaded exact seed images"
		}
		for _, item := range []struct {
			id    string
			label string
		}{
			{id: "seed-forgejo", label: "Forgejo"},
			{id: "seed-harbor", label: "Seed Harbor"},
		} {
			session.reportUnlocked(progress.Event{
				Phase: progress.Infrastructure,
				ID: item.id,
				Label: item.label,
				Detail: message,
				State: progress.Running,
				BytesCurrent: current,
				BytesTotal: total,
			})
		}
	case strings.HasPrefix(lower, "preparing harbor"):
		report("seed-harbor", "Seed Harbor", detail, progress.Running)
	case strings.Contains(lower, "reconciling forgejo administrator"):
		report("seed-forgejo", "Forgejo", "reconciling administrator", progress.Running)
	case strings.Contains(lower, "timeout"), strings.HasPrefix(lower, "invalid "):
		report("seed-forgejo", "Forgejo", detail, progress.Failed)
		report("seed-harbor", "Seed Harbor", detail, progress.Failed)
	}
	return true
}

func seedPlaneBytes(detail string) int64 {
	for _, field := range strings.Fields(detail) {
		raw, found := strings.CutPrefix(field, "bytes=")
		if !found {
			continue
		}
		value, err := strconv.ParseInt(raw, 10, 64)
		if err == nil && value > 0 {
			return value
		}
	}
	return 0
}

func reportSeedService(
	report func(string, string, string, progress.State),
	id, label, state string,
) {
	if strings.HasPrefix(state, "ready") {
		report(id, label, "healthy", progress.Complete)
		return
	}
	report(id, label, state, progress.Running)
}

func ansiblePullDetail(line string) (string, bool) {
	const prefix = `"msg": "Pull `
	const separator = ` required is: `
	if !strings.HasPrefix(line, prefix) {
		return "", false
	}
	payload := strings.TrimSuffix(strings.TrimPrefix(line, prefix), `"`)
	separatorIndex := strings.LastIndex(payload, separator)
	if separatorIndex <= 0 {
		return "", false
	}
	image := payload[:separatorIndex]
	required := payload[separatorIndex+len(separator):]
	if strings.EqualFold(required, "true") {
		return "pulling " + image, true
	}
	return "using cached " + image, true
}

func ansibleActivity(command process.Command) progress.Target {
	if command.Activity.ID != "" {
		return command.Activity
	}
	return progress.Target{Phase: progress.Orchestration, ID: "activity", Label: "Ansible activity"}
}

func (parser *outputParser) emitActivity(session *Session, activity progress.Target) {
	parser.mu.Lock()
	defer parser.mu.Unlock()
	line := parser.activity
	parser.activityTimer = nil
	if line == "" {
		return
	}
	detail := line
	if open, close := strings.IndexByte(line, '['), strings.IndexByte(line, ']'); open >= 0 && close > open {
		detail = line[open+1 : close]
	}
	session.reportUnlocked(progress.Event{
		Phase: activity.Phase, ID: activity.ID, Label: activity.Label,
		Detail: detail, State: progress.Running,
	})
}

func (parser *outputParser) finishCommand(session *Session, command process.Command, commandErr error) {
	if !ansibleCommand(command.Name) {
		return
	}
	parser.mu.Lock()
	defer parser.mu.Unlock()
	parser.activity = ""
	parser.nodeStage = ansibleNodeIdle
	if parser.activityTimer != nil {
		parser.activityTimer.Stop()
		parser.activityTimer = nil
	}
	state := progress.Complete
	detail := "playbook complete; health check pending"
	if commandErr != nil {
		state = progress.Failed
		detail = "playbook failed"
	}
	for host := range parser.activeNodes {
		parser.reportNode(session, host, state, detail)
	}
	clear(parser.activeNodes)
}

func ansibleCommand(name string) bool {
	return name == "ansible-playbook" || strings.HasSuffix(name, "/ansible-playbook")
}

func ansibleTaskDetail(line string) (string, bool) {
	if !strings.HasPrefix(line, "TASK [") && !strings.HasPrefix(line, "PLAY [") &&
		!strings.HasPrefix(line, "RUNNING HANDLER [") {
		return "", false
	}
	open := strings.IndexByte(line, '[')
	close := strings.LastIndexByte(line, ']')
	if open < 0 || close <= open {
		return "", true
	}
	return line[open+1 : close], true
}

func ansibleNodeStageFor(task string) ansibleNodeStage {
	task = strings.ToLower(task)
	switch {
	case strings.Contains(task, "uncordon"):
		return ansibleNodeUncordon
	case strings.Contains(task, "cordon"):
		return ansibleNodeCordon
	case strings.Contains(task, "drain"):
		return ansibleNodeDrain
	case strings.Contains(task, "kubeadm") && strings.Contains(task, "upgrade"):
		return ansibleNodeUpgrade
	default:
		return ansibleNodeIdle
	}
}

func (stage ansibleNodeStage) startDetail() string {
	switch stage {
	case ansibleNodeCordon:
		return "cordoning"
	case ansibleNodeDrain:
		return "draining workloads"
	case ansibleNodeUpgrade:
		return "upgrading Kubernetes components"
	case ansibleNodeUncordon:
		return "validating and uncordoning"
	default:
		return "upgrading"
	}
}

func (stage ansibleNodeStage) completion() (progress.State, string) {
	switch stage {
	case ansibleNodeCordon:
		return progress.Running, "cordoned; preparing to drain"
	case ansibleNodeDrain:
		return progress.Running, "drained; upgrading components"
	case ansibleNodeUpgrade:
		return progress.Running, "components upgraded; validating node"
	case ansibleNodeUncordon:
		return progress.Complete, "upgrade complete; schedulable"
	default:
		return progress.Running, "upgrading"
	}
}

func (parser *outputParser) observeAnsibleResult(session *Session, line string) {
	host := ansibleResultHost(line)
	if host == "" {
		return
	}
	if strings.Contains(line, "Drain node") ||
		(parser.nodeStage == ansibleNodeCordon && strings.HasPrefix(line, "ASYNC ")) {
		parser.nodeStage = ansibleNodeDrain
	}
	if parser.nodeStage == ansibleNodeIdle {
		return
	}
	if strings.HasPrefix(line, "fatal: [") || strings.HasPrefix(line, "failed: [") ||
		strings.HasPrefix(line, "ASYNC FAILED on ") {
		parser.reportNode(session, host, progress.Failed, parser.nodeStage.startDetail()+" failed")
		return
	}
	if strings.HasPrefix(line, "FAILED - RETRYING: [") {
		detail := parser.nodeStage.startDetail() + "; retrying"
		if open := strings.LastIndexByte(line, '('); open >= 0 {
			if close := strings.LastIndexByte(line, ')'); close > open {
				detail += " " + line[open+1:close]
			}
		}
		parser.reportNode(session, host, progress.Running, detail)
		return
	}
	if strings.HasPrefix(line, "ASYNC POLL on ") {
		parser.reportNode(session, host, progress.Running, parser.nodeStage.startDetail()+"; waiting")
		return
	}
	state, detail := parser.nodeStage.completion()
	parser.reportNode(session, host, state, detail)
}

func ansibleResultHost(line string) string {
	var raw string
	switch {
	case strings.HasPrefix(line, "ok: ["), strings.HasPrefix(line, "changed: ["),
		strings.HasPrefix(line, "fatal: ["), strings.HasPrefix(line, "failed: ["),
		strings.HasPrefix(line, "skipping: ["), strings.HasPrefix(line, "FAILED - RETRYING: ["):
		open := strings.IndexByte(line, '[')
		close := strings.IndexByte(line[open+1:], ']')
		if close < 0 {
			return ""
		}
		raw = line[open+1 : open+1+close]
	case strings.HasPrefix(line, "ASYNC POLL on "), strings.HasPrefix(line, "ASYNC OK on "),
		strings.HasPrefix(line, "ASYNC FAILED on "):
		start := strings.Index(line, " on ") + len(" on ")
		end := strings.IndexByte(line[start:], ':')
		if end < 0 {
			return ""
		}
		raw = line[start : start+end]
	case strings.HasPrefix(line, "included: "):
		start := strings.LastIndex(line, " for ")
		if start < 0 {
			return ""
		}
		raw = line[start+len(" for "):]
		if end := strings.IndexAny(raw, " =>"); end >= 0 {
			raw = raw[:end]
		}
	default:
		return ""
	}
	if delegated := strings.Index(raw, " -> "); delegated >= 0 {
		raw = raw[:delegated]
	}
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > 253 {
		return ""
	}
	return raw
}

func (parser *outputParser) reportNode(session *Session, host string, state progress.State, detail string) {
	if _, found := parser.activeNodes[host]; !found {
		if state == progress.Complete || len(parser.activeNodes) >= observedResourceLimit {
			return
		}
		parser.activeNodes[host] = struct{}{}
	}
	if state != progress.Running {
		delete(parser.activeNodes, host)
	}
	session.reportUnlocked(progress.Event{
		Phase:  progress.Orchestration,
		ID:     "node:" + host,
		Label:  "Node " + host,
		Detail: detail,
		State:  state,
	})
}

func (parser *outputParser) updateResource(
	session *Session,
	address string,
	state progress.State,
	detail string,
) {
	if strings.HasPrefix(address, "terraform_data.seed_plane") {
		if state == progress.Running && parser.seedActivity {
			return
		}
		for _, item := range []struct{ id, label string }{
			{id: "seed-forgejo", label: "Forgejo"},
			{id: "seed-harbor", label: "Seed Harbor"},
		} {
			session.reportUnlocked(progress.Event{
				Phase: progress.Infrastructure, ID: item.id, Label: item.label,
				Detail: detail, State: state,
			})
		}
		return
	}
	id, label, aggregate := terraformResource(address)
	if id == "" {
		return
	}
	set := parser.resources[id]
	if set == nil {
		set = &resourceSet{
			expected: make(map[string]struct{}),
			complete: make(map[string]struct{}),
			failed:   make(map[string]struct{}),
		}
		parser.resources[id] = set
	}
	if _, found := set.expected[address]; !found && len(set.expected) >= observedResourceLimit {
		return
	}
	set.expected[address] = struct{}{}
	switch state {
	case progress.Complete:
		set.complete[address] = struct{}{}
		delete(set.failed, address)
	case progress.Failed:
		set.failed[address] = struct{}{}
		delete(set.complete, address)
	default:
		delete(set.failed, address)
		delete(set.complete, address)
	}
	aggregateState := progress.Running
	if len(set.failed) != 0 {
		aggregateState = progress.Failed
	} else if len(set.expected) != 0 && len(set.complete) == len(set.expected) {
		aggregateState = progress.Complete
	}
	event := progress.Event{
		Phase: progress.Infrastructure, ID: id, Label: label,
		Detail: detail, State: aggregateState,
	}
	if aggregate {
		event.Current = len(set.complete)
		event.Total = len(set.expected)
	}
	session.reportUnlocked(event)
}

func terraformResource(address string) (id, label string, aggregate bool) {
	switch {
	case strings.HasPrefix(address, "libvirt_network."):
		return "network", "Network", false
	case strings.HasPrefix(address, "libvirt_domain.load_balancer"):
		return "load-balancer", "Load balancer", false
	case strings.HasPrefix(address, "libvirt_domain.bastion"):
		return "bastion", "Bastion", false
	case strings.HasPrefix(address, "libvirt_domain.node["):
		return "nodes", "Nodes", true
	case strings.HasPrefix(address, "libvirt_volume.") || strings.HasPrefix(address, "libvirt_cloudinit_disk."):
		return "storage", "Storage", true
	default:
		return "", "", false
	}
}
