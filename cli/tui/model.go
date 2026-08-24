package tui

import (
	"fmt"
	"strings"
	"time"

	"atum/cli/progress"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
)

const frameInterval = time.Second

var (
	accentColor  = lipgloss.AdaptiveColor{Light: "#005F87", Dark: "#5FD7FF"}
	mutedColor   = lipgloss.AdaptiveColor{Light: "#6C6C6C", Dark: "#8A8A8A"}
	successColor = lipgloss.AdaptiveColor{Light: "#008700", Dark: "#5FD75F"}
	failureColor = lipgloss.AdaptiveColor{Light: "#AF0000", Dark: "#FF5F5F"}

	titleStyle   = lipgloss.NewStyle().Bold(true).Foreground(accentColor)
	headingStyle = lipgloss.NewStyle().Bold(true)
	mutedStyle   = lipgloss.NewStyle().Foreground(mutedColor)
	successStyle = lipgloss.NewStyle().Foreground(successColor)
	failureStyle = lipgloss.NewStyle().Foreground(failureColor)
	rowStyle     = lipgloss.NewStyle().Inline(true)
)

type itemModel struct {
	id      string
	label   string
	detail  string
	state   progress.State
	current int
	total   int
	updated time.Time
}

type phaseModel struct {
	id      progress.Phase
	label   string
	visible bool
	order   []string
	items   map[string]*itemModel
}

type finishMsg struct{ err error }
type tickMsg time.Time

type queuedProgress struct {
	sequence uint64
	event    progress.Event
}

type progressBatchMsg []queuedProgress

type model struct {
	title    string
	logPath  string
	phases   []*phaseModel
	byPhase  map[progress.Phase]*phaseModel
	start    time.Time
	width    int
	height   int
	frame    int
	ticking  bool
	finished bool
	canceled bool
	showLogs bool
	logs     logSnapshotMsg
	lastItem string
	lastAt   time.Time
	err      error
	cancel   func()
}

func newModel(title, logPath string, specs []phaseSpec, cancel func()) *model {
	result := &model{
		title: title, logPath: logPath, start: time.Now(), width: 100, height: 24,
		phases:  make([]*phaseModel, 0, len(specs)),
		byPhase: make(map[progress.Phase]*phaseModel, len(specs)), cancel: cancel,
	}
	for _, spec := range specs {
		phase := &phaseModel{
			id: spec.id, label: spec.label,
			order: make([]string, 0, len(spec.items)),
			items: make(map[string]*itemModel, len(spec.items)),
		}
		for _, item := range spec.items {
			phase.order = append(phase.order, item.id)
			phase.items[item.id] = &itemModel{id: item.id, label: item.label, state: progress.Pending}
		}
		result.phases = append(result.phases, phase)
		result.byPhase[phase.id] = phase
	}
	return result
}

func (model *model) Init() tea.Cmd {
	model.ticking = true
	return tick()
}

func tick() tea.Cmd {
	return tea.Tick(frameInterval, func(now time.Time) tea.Msg { return tickMsg(now) })
}

func (model *model) Update(message tea.Msg) (tea.Model, tea.Cmd) {
	switch message := message.(type) {
	case tea.WindowSizeMsg:
		model.width = max(message.Width, 40)
		model.height = max(message.Height, 10)
	case tea.KeyMsg:
		switch message.String() {
		case "l":
			model.showLogs = !model.showLogs
		case "q", "ctrl+c":
			if model.finished || model.canceled {
				break
			}
			model.canceled = true
			if model.cancel != nil {
				model.cancel()
			}
			return model, tea.Quit
		}
	case progress.Event:
		model.apply(message)
		if message.State == progress.Running && !model.ticking {
			model.ticking = true
			return model, tick()
		}
	case progressBatchMsg:
		running := false
		for _, queued := range message {
			model.apply(queued.event)
			running = running || queued.event.State == progress.Running
		}
		if running && !model.ticking {
			model.ticking = true
			return model, tick()
		}
	case logSnapshotMsg:
		model.logs = message
	case tickMsg:
		model.frame++
		model.ticking = false
		if !model.finished && !model.canceled {
			model.ticking = true
			return model, tick()
		}
	case finishMsg:
		model.finished = true
		model.err = message.err
		for _, phase := range model.phases {
			for _, id := range phase.order {
				item := phase.items[id]
				if item.state != progress.Running {
					continue
				}
				if message.err == nil {
					item.state = progress.Complete
				} else {
					item.state = progress.Failed
					item.detail = message.err.Error()
				}
			}
		}
		return model, tea.Quit
	}
	return model, nil
}

func (model *model) apply(event progress.Event) {
	phase := model.byPhase[event.Phase]
	if phase == nil {
		phase = &phaseModel{id: event.Phase, label: displayName(string(event.Phase)), items: make(map[string]*itemModel)}
		model.byPhase[event.Phase] = phase
		model.phases = append(model.phases, phase)
	}
	phase.visible = true
	model.lastItem = event.Label
	if model.lastItem == "" {
		if event.ID == "*" {
			model.lastItem = phase.label
		} else {
			model.lastItem = displayName(event.ID)
		}
	}
	model.lastAt = event.Time
	if model.lastAt.IsZero() {
		model.lastAt = time.Now()
	}
	if event.ID == "*" {
		for _, id := range phase.order {
			item := phase.items[id]
			if item.state == progress.Complete || item.state == progress.Failed {
				continue
			}
			item.state = event.State
			if event.Detail != "" {
				item.detail = event.Detail
			}
		}
		return
	}
	item := phase.items[event.ID]
	if item == nil {
		label := event.Label
		if label == "" {
			label = displayName(event.ID)
		}
		item = &itemModel{id: event.ID, label: label}
		phase.items[event.ID] = item
		phase.order = append(phase.order, event.ID)
	}
	if event.Label != "" {
		item.label = event.Label
	}
	// Completed and failed rows reject late generic updates from subprocesses.
	// An explicit Start event opens a new lifecycle when a managed operation
	// intentionally reuses a semantic row later in the same command session.
	if (item.state == progress.Complete || item.state == progress.Failed) &&
		event.State == progress.Running && !event.Restart {
		return
	}
	item.state = event.State
	item.detail = event.Detail
	item.current = event.Current
	item.total = event.Total
	item.updated = event.Time
}

func (model *model) running() bool {
	if model.finished {
		return false
	}
	for _, phase := range model.phases {
		for _, id := range phase.order {
			if phase.items[id].state == progress.Running {
				return true
			}
		}
	}
	return false
}

func (model *model) View() string {
	width := max(model.width, 40)
	sections := make([]string, 0, len(model.phases)+2)
	elapsed := time.Since(model.start).Round(time.Second)
	state := "running"
	stateStyle := mutedStyle
	if model.canceled && !model.finished {
		state = "canceling"
	}
	if model.finished {
		if model.err == nil {
			state = "complete"
			stateStyle = successStyle
		} else {
			state = "failed"
			stateStyle = failureStyle
		}
	}
	stateIcon := ""
	if !model.finished {
		stateIcon = model.spinner() + " "
	}
	header := titleStyle.Render("Atum") + "  " + headingStyle.Render(model.title) + "  " +
		stateStyle.Render(stateIcon+state) + mutedStyle.Render("  "+elapsed.String())
	sections = append(sections, lipgloss.NewStyle().Inline(true).MaxWidth(width).Render(header))
	if model.showLogs {
		sections = append(sections, model.renderLogs(width))
	} else {
		for _, phase := range model.phases {
			if phase.visible {
				sections = append(sections, model.renderPhase(phase, width))
			}
		}
		if len(sections) == 1 {
			sections = append(sections, mutedStyle.Render("  waiting for the first phase update"))
		} else if !model.finished && !model.running() {
			sections = append(sections, model.renderQuietActivity(width))
		}
	}
	footer := "raw log  " + model.logPath
	if !model.finished {
		logAction := "show logs"
		if model.showLogs {
			logAction = "hide logs"
		}
		footer = "l " + logAction + "   q/ctrl+c hard exit   " + footer
	}
	sections = append(sections, mutedStyle.Inline(true).MaxWidth(width).Render(footer))
	return strings.Join(sections, "\n\n") + "\n"
}

func (model *model) spinner() string {
	frames := [...]string{"◐", "◓", "◑", "◒"}
	return frames[model.frame%len(frames)]
}

func (model *model) renderQuietActivity(width int) string {
	detail := "waiting for the next progress update"
	if model.lastItem != "" {
		detail = "continuing after " + model.lastItem
		if !model.lastAt.IsZero() {
			detail += " · " + time.Since(model.lastAt).Round(time.Second).String() + " since update"
		}
	}
	line := titleStyle.Render(model.spinner()) + " " + headingStyle.Render("Provisioning continues") +
		mutedStyle.Render("  "+detail)
	return lipgloss.NewStyle().Inline(true).MaxWidth(width).Render(line)
}

func (model *model) renderLogs(width int) string {
	lineLimit := max(model.height-7, 1)
	available := model.logs.count
	if model.logs.partial != "" {
		available++
	}
	lineLimit = min(lineLimit, available)
	lines := make([]string, 0, lineLimit+1)
	lines = append(lines, headingStyle.Render("Streaming raw log"))
	if lineLimit == 0 {
		return strings.Join(append(lines, mutedStyle.Render("waiting for log output")), "\n")
	}
	first := available - lineLimit
	for offset := first; offset < available; offset++ {
		line := model.logs.partial
		if offset < model.logs.count {
			index := (model.logs.start + offset) % logTailLineLimit
			line = model.logs.lines[index]
		}
		lines = append(lines, mutedStyle.Render(ansi.Truncate(line, width, "…")))
	}
	return strings.Join(lines, "\n")
}

func (model *model) renderPhase(phase *phaseModel, width int) string {
	const columnGap = 2
	complete := 0
	for _, id := range phase.order {
		if phase.items[id].state == progress.Complete {
			complete++
		}
	}
	heading := fmt.Sprintf("%s  %d/%d", phase.label, complete, len(phase.order))
	rows := make([]string, 0, len(phase.order))
	for _, id := range phase.order {
		rows = append(rows, model.renderItem(phase.items[id]))
	}
	columns := 1
	if width >= 112 && len(rows) >= 9 {
		columns = 3
	} else if width >= 76 && len(rows) >= 6 {
		columns = 2
	}
	columnWidth := max((width-(columns-1)*columnGap)/columns, 24)
	columnHeight := (len(rows) + columns - 1) / columns
	rendered := make([]string, 0, columns)
	for column := range columns {
		start := column * columnHeight
		if start >= len(rows) {
			break
		}
		end := min(start+columnHeight, len(rows))
		content := make([]string, 0, columnHeight)
		for _, row := range rows[start:end] {
			content = append(content, rowStyle.Width(columnWidth).MaxWidth(columnWidth).Render(row))
		}
		columnBody := strings.Join(content, "\n")
		if column < columns-1 {
			columnBody = lipgloss.NewStyle().PaddingRight(columnGap).Render(columnBody)
		}
		rendered = append(rendered, columnBody)
	}
	body := lipgloss.JoinHorizontal(lipgloss.Top, rendered...)
	return headingStyle.Render(heading) + "\n" + body
}

func (model *model) renderItem(item *itemModel) string {
	icon := mutedStyle.Render("○")
	switch item.state {
	case progress.Running:
		icon = titleStyle.Render(model.spinner())
	case progress.Complete:
		icon = successStyle.Render("✓")
	case progress.Failed:
		icon = failureStyle.Render("✗")
	}
	detail := item.detail
	if item.total > 0 {
		count := fmt.Sprintf("%d/%d", item.current, item.total)
		if detail == "" {
			detail = count
		} else {
			detail = count + " " + detail
		}
	}
	if item.state == progress.Running && !item.updated.IsZero() {
		elapsed := time.Since(item.updated).Round(time.Second)
		if elapsed >= time.Second {
			if detail == "" {
				detail = "waiting " + elapsed.String()
			} else {
				detail += " · " + elapsed.String()
			}
		}
	}
	row := icon + " " + item.label
	if detail != "" {
		row += mutedStyle.Render("  " + detail)
	}
	return row
}
