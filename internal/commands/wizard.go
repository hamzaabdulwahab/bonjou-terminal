package commands

import (
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/huh"
	"github.com/charmbracelet/lipgloss"
	"golang.org/x/term"

	"github.com/hamzawahab/bonjou-cli/internal/network"
)

// This file holds everything that belongs to the @wizard subsystem: the
// state machine that drives the interactive flows, the bubbletea/huh
// glue, the alt-screen render wrapper, the theming, and the small layout
// utilities for picking a width on the current terminal.

// Wizard error sentinels returned by sub-flows. Callers use errors.Is to
// branch on them (no string-matching against error messages).
var (
	errWizardExit        = errors.New("wizard exit")
	errWizardNoPeers     = errors.New("wizard no active peers")
	errWizardBack        = errors.New("wizard back")
	errWizardNoSelection = errors.New("wizard no recipients selected")

	wizardActiveFlag  bool
	wizardActiveMu    sync.Mutex
	wizardExitHooks   []func()
	wizardExitHooksMu sync.Mutex
)

const wizardBackValue = "__wizard_back__"

const (
	wizardMinWidth  = 1
	wizardMinHeight = 8

	// Side margin reserved when scaling the wizard to the terminal width.
	// Two columns on each side gives the rounded border breathing room from
	// the screen edge without leaving big empty bands of background.
	wizardSideMargin = 4

	// Minimum render widths. Below these the form's content doesn't lay out
	// cleanly. There is no fixed maximum — the wizard expands to fill the
	// terminal so the pink border spans the visible width on wide screens.
	wizardMenuMinWidth    = 36
	wizardMessageMinWidth = 40

	wizardMessageLineCount = 5

	// Width used to truncate peer labels so they fit even in the narrowest
	// wizard layout. Kept as a constant so peer-label rendering is stable
	// across terminal sizes.
	wizardLabelWidth = 28
)

// RegisterWizardExitHook arranges for fn to be invoked every time the
// wizard transitions from active to inactive. The UI uses this to flush
// any events it buffered while the wizard owned the alt screen so they
// reappear on the main scrollback once the wizard closes.
func RegisterWizardExitHook(fn func()) {
	if fn == nil {
		return
	}
	wizardExitHooksMu.Lock()
	wizardExitHooks = append(wizardExitHooks, fn)
	wizardExitHooksMu.Unlock()
}

func runWizardExitHooks() {
	wizardExitHooksMu.Lock()
	hooks := append([]func(){}, wizardExitHooks...)
	wizardExitHooksMu.Unlock()
	for _, fn := range hooks {
		fn()
	}
}

// WizardRenderActive reports whether the wizard is currently running on
// the alt screen. While true, the main UI must not write to the terminal
// — doing so would corrupt the wizard's rendering and leave artifacts
// when the alt screen is restored.
func WizardRenderActive() bool {
	wizardActiveMu.Lock()
	defer wizardActiveMu.Unlock()
	return wizardActiveFlag
}

func setWizardActive(active bool) {
	wizardActiveMu.Lock()
	wasActive := wizardActiveFlag
	wizardActiveFlag = active
	wizardActiveMu.Unlock()
	if wasActive && !active {
		runWizardExitHooks()
	}
}

// cmdWizard is the entry point for `@wizard`. It loops until the user
// either exits cleanly or aborts the form. Between iterations a status
// message can be carried forward into the menu's description so the user
// sees the outcome of the previous action without it being lost when the
// alt screen flashes away and back.
func (h *Handler) cmdWizard() (Result, error) {
	status := ""
	for {
		action := ""
		description := "Choose action. Ctrl+C exits."
		if status != "" {
			description = status + "\n\n" + description
		}

		if err := runWizardForm(
			huh.NewForm(
				huh.NewGroup(
					huh.NewSelect[string]().
						Title("Bonjou Wizard").
						Description(description).
						Options(
							huh.NewOption("Send message", "message"),
							huh.NewOption("Send file", "file"),
							huh.NewOption("Send folder", "folder"),
							huh.NewOption("Send to multiple users", "multi"),
							huh.NewOption("Broadcast", "broadcast"),
						).
						Value(&action),
				),
			),
		); err != nil {
			return Result{Output: "Wizard closed. Returned to command prompt."}, nil
		}

		var actionStatus string
		var err error
		switch action {
		case "message":
			actionStatus, err = h.wizardSendSingle("message")
		case "file":
			actionStatus, err = h.wizardSendSingle("file")
		case "folder":
			actionStatus, err = h.wizardSendSingle("folder")
		case "multi":
			actionStatus, err = h.wizardSendMulti()
		case "broadcast":
			actionStatus, err = h.wizardSendBroadcast()
		default:
			actionStatus = fmt.Sprintf("Unsupported wizard action: %s", action)
		}

		if errors.Is(err, errWizardExit) {
			return Result{Output: "Wizard closed. Returned to command prompt."}, nil
		}
		if errors.Is(err, errWizardBack) {
			status = wizardStatusInfo("Back to wizard menu.")
			continue
		}
		if err != nil {
			status = wizardStatusError(err.Error())
			continue
		}

		status = strings.TrimSpace(actionStatus)
		if status == "" {
			h.waitForWizardEventFlush(900 * time.Millisecond)
			status = ""
			continue
		}
	}
}

// waitForWizardEventFlush pauses briefly after a wizard action so the
// next menu doesn't re-enter alt screen on top of in-flight transfer
// events. The 25ms poll is well under bubbletea's render tick so it
// doesn't introduce perceivable lag.
func (h *Handler) waitForWizardEventFlush(timeout time.Duration) {
	if h == nil || h.session == nil || h.session.Events == nil {
		return
	}
	deadline := time.Now().Add(timeout)
	quietReads := 0
	for time.Now().Before(deadline) {
		if len(h.session.Events) == 0 {
			quietReads++
			if quietReads >= 3 {
				return
			}
		} else {
			quietReads = 0
		}
		time.Sleep(25 * time.Millisecond)
	}
}

func (h *Handler) wizardSendSingle(kind string) (string, error) {
	peer, err := h.wizardSelectPeer("Choose recipient")
	if err != nil {
		if errors.Is(err, errWizardNoPeers) {
			return wizardStatusError("No active users discovered. Use @users to refresh discovery and try again."), nil
		}
		if errors.Is(err, errWizardBack) {
			return "", errWizardBack
		}
		if errors.Is(err, errWizardExit) {
			return "", errWizardExit
		}
		return "", err
	}

	confirmed := false
	submitLabel := "Submit"

	switch kind {
	case "message":
		message, err := wizardMessageInput("Message", "Type your message")
		if err != nil {
			if errors.Is(err, errWizardBack) {
				return "", errWizardBack
			}
			if errors.Is(err, errWizardExit) {
				return "", errWizardExit
			}
			return "", err
		}
		confirmed, err = wizardConfirm("Send message now?", submitLabel)
		if err != nil {
			if errors.Is(err, errWizardExit) {
				return "", errWizardExit
			}
			return "", err
		}
		if !confirmed {
			return wizardStatusInfo("Cancelled. Nothing was sent."), nil
		}
		if err := h.session.Transfer.SendMessage(peer, message); err != nil {
			return wizardStatusError(fmt.Sprintf("Failed to send message to %s: %v", peerLabel(peer), err)), nil
		}
		return "", nil
	case "file":
		path, err := wizardPathInput("File path", "~/Downloads/example.txt", false)
		if err != nil {
			if errors.Is(err, errWizardBack) {
				return "", errWizardBack
			}
			if errors.Is(err, errWizardExit) {
				return "", errWizardExit
			}
			return "", err
		}
		confirmed, err = wizardConfirm("Send file now?", submitLabel)
		if err != nil {
			if errors.Is(err, errWizardExit) {
				return "", errWizardExit
			}
			return "", err
		}
		if !confirmed {
			return wizardStatusInfo("Cancelled. Nothing was sent."), nil
		}
		if err := h.session.Transfer.SendFile(peer, path); err != nil {
			return "", nil
		}
		return "", nil
	case "folder":
		path, err := wizardPathInput("Folder path", "~/Downloads/my-folder", true)
		if err != nil {
			if errors.Is(err, errWizardBack) {
				return "", errWizardBack
			}
			if errors.Is(err, errWizardExit) {
				return "", errWizardExit
			}
			return "", err
		}
		confirmed, err = wizardConfirm("Send folder now?", submitLabel)
		if err != nil {
			if errors.Is(err, errWizardExit) {
				return "", errWizardExit
			}
			return "", err
		}
		if !confirmed {
			return wizardStatusInfo("Cancelled. Nothing was sent."), nil
		}
		if err := h.session.Transfer.SendFolder(peer, path); err != nil {
			return "", nil
		}
		return "", nil
	default:
		return "", fmt.Errorf("unsupported single wizard kind: %s", kind)
	}
}

func (h *Handler) wizardSendMulti() (string, error) {
	for {
		peers, err := h.wizardSelectPeers("Choose recipients")
		if err != nil {
			if errors.Is(err, errWizardNoPeers) {
				return wizardStatusError("No active users discovered. Use @users to refresh discovery and try again."), nil
			}
			if errors.Is(err, errWizardNoSelection) {
				return wizardStatusError("No recipients selected."), nil
			}
			if errors.Is(err, errWizardBack) {
				return "", errWizardBack
			}
			if errors.Is(err, errWizardExit) {
				return "", errWizardExit
			}
			return "", err
		}

		for {
			transferKind, err := wizardSelectMultiTransferKind()
			if err != nil {
				if errors.Is(err, errWizardBack) {
					break
				}
				if errors.Is(err, errWizardExit) {
					return "", errWizardExit
				}
				return "", err
			}

			message := ""
			path := ""
			switch transferKind {
			case "message":
				message, err = wizardMessageInput("Message", "Type your message")
				if err != nil {
					if errors.Is(err, errWizardBack) {
						continue
					}
					if errors.Is(err, errWizardExit) {
						return "", errWizardExit
					}
					return "", err
				}
			case "file":
				path, err = wizardPathInput("File path", "~/Downloads/example.txt", false)
				if err != nil {
					if errors.Is(err, errWizardBack) {
						continue
					}
					if errors.Is(err, errWizardExit) {
						return "", errWizardExit
					}
					return "", err
				}
			case "folder":
				path, err = wizardPathInput("Folder path", "~/Downloads/my-folder", true)
				if err != nil {
					if errors.Is(err, errWizardBack) {
						continue
					}
					if errors.Is(err, errWizardExit) {
						return "", errWizardExit
					}
					return "", err
				}
			default:
				return "", fmt.Errorf("unsupported multi wizard kind: %s", transferKind)
			}

			confirmed, err := wizardConfirm("Send now?", "Submit")
			if err != nil {
				if errors.Is(err, errWizardExit) {
					return "", errWizardExit
				}
				return "", err
			}
			if !confirmed {
				return wizardStatusInfo("Cancelled. Nothing was sent."), nil
			}

			success, errs := h.sendToPeers(peers, transferKind, message, path)
			if len(errs) > 0 {
				return wizardStatusError(fmt.Sprintf("Completed %d transfers, %d errors: %s", success, len(errs), strings.Join(errs, " | "))), nil
			}
			return "", nil
		}
	}
}

func (h *Handler) wizardSendBroadcast() (string, error) {
	message, err := wizardMessageInput("Broadcast message", "Type your message")
	if err != nil {
		if errors.Is(err, errWizardBack) {
			return "", errWizardBack
		}
		if errors.Is(err, errWizardExit) {
			return "", errWizardExit
		}
		return "", err
	}

	confirmed, err := wizardConfirm("Send to all discovered users?", "Send to all")
	if err != nil {
		if errors.Is(err, errWizardExit) {
			return "", errWizardExit
		}
		return "", err
	}
	if !confirmed {
		return wizardStatusInfo("Cancelled. Nothing was sent."), nil
	}

	result, err := h.cmdBroadcast(message)
	if err != nil {
		return wizardStatusError(fmt.Sprintf("Broadcast failed: %v", err)), nil
	}
	if strings.TrimSpace(result.Output) == "" {
		return wizardStatusInfo("Broadcast sent."), nil
	}
	if strings.EqualFold(strings.TrimSpace(result.Output), "No peers to broadcast to.") {
		return wizardStatusError("No active users discovered. Use @users to refresh discovery and try again."), nil
	}
	if strings.HasPrefix(strings.TrimSpace(result.Output), "Broadcast completed with errors:") {
		return wizardStatusError(result.Output), nil
	}
	return wizardStatusInfo(result.Output), nil
}

func (h *Handler) wizardSelectPeer(title string) (*network.Peer, error) {
	peers := h.sortedPeers()
	if len(peers) == 0 {
		return nil, errWizardNoPeers
	}

	selectedIP := ""
	options := make([]huh.Option[string], 0, len(peers))
	options = append(options, huh.NewOption("Back", wizardBackValue))
	for _, peer := range peers {
		label := wizardPeerLabel(peer)
		options = append(options, huh.NewOption(label, peer.IP))
	}

	if err := runWizardForm(
		huh.NewForm(
			huh.NewGroup(
				huh.NewSelect[string]().
					Title(title).
					Description("Choose recipient.").
					Options(options...).
					Value(&selectedIP),
			),
		),
	); err != nil {
		return nil, errWizardExit
	}
	if selectedIP == wizardBackValue {
		return nil, errWizardBack
	}

	return h.resolvePeer(selectedIP)
}

func (h *Handler) wizardSelectPeers(title string) ([]*network.Peer, error) {
	peers := h.sortedPeers()
	if len(peers) == 0 {
		return nil, errWizardNoPeers
	}

	backToMenu := false
	if err := runWizardForm(
		huh.NewForm(
			huh.NewGroup(
				huh.NewConfirm().
					Title(title).
					Description("Choose recipients.").
					Affirmative("Select recipients").
					Negative("Back").
					Value(&backToMenu),
			),
		),
	); err != nil {
		return nil, errWizardExit
	}
	if !backToMenu {
		return nil, errWizardBack
	}

	selectedIPs := make([]string, 0)
	options := make([]huh.Option[string], 0, len(peers))
	for _, peer := range peers {
		label := wizardPeerLabel(peer)
		options = append(options, huh.NewOption(label, peer.IP))
	}

	if err := runWizardForm(
		huh.NewForm(
			huh.NewGroup(
				huh.NewMultiSelect[string]().
					Title(title).
					Description("Pick one or more.").
					Options(options...).
					Value(&selectedIPs),
			),
		),
	); err != nil {
		return nil, errWizardExit
	}

	if len(selectedIPs) == 0 {
		return nil, errWizardNoSelection
	}

	selectedPeers := make([]*network.Peer, 0, len(selectedIPs))
	for _, ip := range selectedIPs {
		peer, err := h.resolvePeer(ip)
		if err != nil {
			return nil, err
		}
		selectedPeers = append(selectedPeers, peer)
	}

	return selectedPeers, nil
}

func (h *Handler) sortedPeers() []network.Peer {
	peers := h.session.Discovery.ListPeers()
	sort.Slice(peers, func(i, j int) bool {
		left := strings.ToLower(strings.TrimSpace(peers[i].Username)) + "|" + peers[i].IP
		right := strings.ToLower(strings.TrimSpace(peers[j].Username)) + "|" + peers[j].IP
		return left < right
	})
	return peers
}

func wizardTextInput(title, placeholder string, validate func(string) error) (string, error) {
	value := ""
	field := huh.NewInput().
		Title(title).
		Description("/back returns to menu.").
		Placeholder(placeholder).
		Value(&value)
	if validate != nil {
		field = field.Validate(func(input string) error {
			if strings.EqualFold(strings.TrimSpace(input), "/back") {
				return nil
			}
			return validate(input)
		})
	}
	if err := runWizardForm(huh.NewForm(huh.NewGroup(field))); err != nil {
		return "", errWizardExit
	}
	trimmed := strings.TrimSpace(value)
	if strings.EqualFold(trimmed, "/back") {
		return "", errWizardBack
	}
	return trimmed, nil
}

func wizardMessageInput(title, placeholder string) (string, error) {
	value := ""
	field := huh.NewText().
		Title(title).
		Description("/back returns to menu. Enter to send, alt/option+Enter for newline.").
		Placeholder(placeholder).
		Lines(wizardMessageLineCount).
		ShowLineNumbers(false).
		Value(&value).
		Validate(func(input string) error {
			normalized := normalizeMessageInput(input)
			if strings.EqualFold(strings.TrimSpace(normalized), "/back") {
				return nil
			}
			if strings.TrimSpace(normalized) == "" {
				return errors.New("message cannot be empty")
			}
			return nil
		})

	if err := runWizardWideForm(huh.NewForm(huh.NewGroup(field))); err != nil {
		return "", errWizardExit
	}

	normalized := normalizeMessageInput(value)
	if strings.EqualFold(strings.TrimSpace(normalized), "/back") {
		return "", errWizardBack
	}
	return normalized, nil
}

func normalizeMessageInput(input string) string {
	normalized := strings.ReplaceAll(input, "\r\n", "\n")
	normalized = strings.ReplaceAll(normalized, "\r", "\n")
	return strings.TrimSpace(normalized)
}

func wizardSelectMultiTransferKind() (string, error) {
	transferKind := ""
	if err := runWizardForm(
		huh.NewForm(
			huh.NewGroup(
				huh.NewSelect[string]().
					Title("What do you want to send?").
					Description("Choose transfer type.").
					Options(
						huh.NewOption("Back", wizardBackValue),
						huh.NewOption("Message", "message"),
						huh.NewOption("File", "file"),
						huh.NewOption("Folder", "folder"),
					).
					Value(&transferKind),
			),
		),
	); err != nil {
		return "", errWizardExit
	}
	if transferKind == wizardBackValue {
		return "", errWizardBack
	}
	return transferKind, nil
}

func (h *Handler) sendToPeers(peers []*network.Peer, transferKind, message, path string) (int, []string) {
	success := 0
	errs := make([]string, 0)

	for _, peer := range peers {
		var err error
		switch transferKind {
		case "message":
			err = h.session.Transfer.SendMessage(peer, message)
		case "file":
			err = h.session.Transfer.SendFile(peer, path)
		case "folder":
			err = h.session.Transfer.SendFolder(peer, path)
		default:
			err = fmt.Errorf("unsupported multi wizard kind: %s", transferKind)
		}
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", peerLabel(peer), err))
			continue
		}
		success++
	}

	return success, errs
}

func wizardPathInput(title, placeholder string, expectDir bool) (string, error) {
	path, err := wizardTextInput(title, placeholder, func(value string) error {
		normalized, err := normalizePathArg(value)
		if err != nil {
			return err
		}
		info, err := os.Stat(normalized)
		if err != nil {
			return err
		}
		if expectDir && !info.IsDir() {
			return errors.New("selected path is not a directory")
		}
		if !expectDir && info.IsDir() {
			return errors.New("selected path is a directory")
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	return normalizePathArg(path)
}

func wizardConfirm(title, submitLabel string) (bool, error) {
	confirmed := false
	if err := runWizardForm(huh.NewForm(
		huh.NewGroup(
			huh.NewConfirm().
				Title(title).
				Description("Ctrl+C exits.").
				Affirmative(submitLabel).
				Negative("Cancel").
				Value(&confirmed),
		),
	)); err != nil {
		return false, errWizardExit
	}
	return confirmed, nil
}

// runWizardForm runs a standard wizard form (menu, peer select, confirm,
// etc.) on the alt screen at the menu width.
func runWizardForm(form *huh.Form) error {
	return runWizardFormWithWidth(form, wizardMenuRenderWidth())
}

// runWizardWideForm runs a wizard form using a wider render width suitable
// for freeform input such as messages, where a narrow box clips text past
// the edge.
func runWizardWideForm(form *huh.Form) error {
	return runWizardFormWithWidth(form, wizardMessageInputWidth())
}

func runWizardFormWithWidth(form *huh.Form, width int) error {
	setWizardActive(true)
	defer setWizardActive(false)

	form.
		WithTheme(wizardTheme()).
		WithWidth(width).
		WithShowHelp(false)
	form.SubmitCmd = tea.Quit
	form.CancelCmd = tea.Interrupt

	// Wrap the form so a tea.ClearScreen Cmd is dispatched alongside every
	// WindowSizeMsg. Bubbletea's standard renderer only invalidates its
	// in-memory cache on resize (repaint), leaving stale borders, wrapped
	// text, and box frames in the alt-screen buffer when the new render is
	// smaller or laid out differently — that's the artifact pattern visible
	// when zooming. Issuing ClearScreen first guarantees a clean canvas.
	wrapper := &altScreenClearModel{inner: form}

	prog := tea.NewProgram(wrapper,
		tea.WithOutput(os.Stderr),
		tea.WithAltScreen(),
		tea.WithFilter(wizardTeaFilter),
		tea.WithReportFocus(),
	)
	finalModel, err := prog.Run()
	if errors.Is(err, tea.ErrInterrupted) {
		return huh.ErrUserAborted
	}
	if err != nil {
		return err
	}
	if w, ok := finalModel.(*altScreenClearModel); ok {
		if f, ok := w.inner.(*huh.Form); ok && f.State == huh.StateAborted {
			return huh.ErrUserAborted
		}
	}
	return nil
}

// altScreenClearModel wraps a tea.Model and dispatches tea.ClearScreen on
// every WindowSizeMsg so the alt screen is wiped before the new render.
// See runWizardFormWithWidth for the rationale.
type altScreenClearModel struct {
	inner tea.Model
}

func (a *altScreenClearModel) Init() tea.Cmd {
	return a.inner.Init()
}

func (a *altScreenClearModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	next, cmd := a.inner.Update(msg)
	a.inner = next
	if _, ok := msg.(tea.WindowSizeMsg); ok {
		return a, tea.Batch(tea.ClearScreen, cmd)
	}
	return a, cmd
}

func (a *altScreenClearModel) View() string {
	return a.inner.View()
}

// wizardMenuRenderWidth returns the form width to use for menu/select/
// confirm forms. It scales with the terminal width so the pink border
// spans most of the screen on wide terminals while still leaving margins.
func wizardMenuRenderWidth() int {
	return wizardRenderWidthFor(terminalColumns(), wizardMenuMinWidth)
}

// wizardMessageInputWidth returns the form width to use for the message-
// entry field. It also fills the terminal so long messages have room to
// wrap.
func wizardMessageInputWidth() int {
	return wizardRenderWidthFor(terminalColumns(), wizardMessageMinWidth)
}

func wizardRenderWidthFor(cols, minW int) int {
	width := cols - wizardSideMargin
	if width < minW {
		width = minW
	}
	return width
}

func terminalColumns() int {
	if cols, _, err := term.GetSize(int(os.Stderr.Fd())); err == nil && cols > 0 {
		return cols
	}
	if cols, _, err := term.GetSize(int(os.Stdout.Fd())); err == nil && cols > 0 {
		return cols
	}
	return 80
}

func wizardTeaFilter(_ tea.Model, msg tea.Msg) tea.Msg {
	size, ok := msg.(tea.WindowSizeMsg)
	if !ok {
		return msg
	}
	if size.Width < wizardMinWidth {
		size.Width = wizardMinWidth
	}
	if size.Height < wizardMinHeight {
		size.Height = wizardMinHeight
	}
	return size
}

func wizardTheme() *huh.Theme {
	t := huh.ThemeCharm()
	pink := lipgloss.AdaptiveColor{Light: "#FF2D96", Dark: "#FF4DA6"}
	white := lipgloss.AdaptiveColor{Light: "#FFFFFF", Dark: "#FFFFFF"}

	// No border on Base/Card. lipgloss draws box borders by computing the
	// content's visible width and stamping ╭─╮ / │ │ / ╰─╯ around it; when
	// the terminal resizes mid-render the cached width and the current
	// width disagree, leaving stale border characters scattered across the
	// alt screen. The user has explicitly asked for a border-free wizard
	// so the layout reflows cleanly at any zoom level. Pink stays — we
	// just apply it to the typography (title, selectors, cursor) instead
	// of to a frame.
	t.Focused.Base = t.Focused.Base.
		UnsetBorderStyle().
		UnsetBorderForeground().
		BorderTop(false).
		BorderRight(false).
		BorderBottom(false).
		BorderLeft(false).
		Padding(0, 0).
		Margin(0)
	t.Focused.Card = t.Focused.Base
	t.Focused.Title = t.Focused.Title.Foreground(pink).Bold(true)
	t.Focused.NoteTitle = t.Focused.NoteTitle.Foreground(pink).Bold(true)
	t.Focused.Description = t.Focused.Description.Foreground(lipgloss.AdaptiveColor{Light: "240", Dark: "245"})
	t.Focused.SelectSelector = t.Focused.SelectSelector.Foreground(pink)
	t.Focused.MultiSelectSelector = t.Focused.MultiSelectSelector.Foreground(pink)
	t.Focused.NextIndicator = t.Focused.NextIndicator.Foreground(pink)
	t.Focused.PrevIndicator = t.Focused.PrevIndicator.Foreground(pink)
	t.Focused.SelectedPrefix = t.Focused.SelectedPrefix.Foreground(pink)
	t.Focused.FocusedButton = t.Focused.FocusedButton.Foreground(white).Background(pink).Bold(true)
	t.Focused.TextInput.Prompt = t.Focused.TextInput.Prompt.Foreground(pink)
	t.Focused.TextInput.Cursor = t.Focused.TextInput.Cursor.Foreground(pink)
	t.Focused.TextInput.CursorText = t.Focused.TextInput.CursorText.Foreground(white).Background(pink)

	// Blurred state mirrors Focused exactly: same colours, same lack of
	// border. Without this, unfocused fields would inherit huh's default
	// hidden-border style and still leak phantom column widths.
	t.Blurred = t.Focused
	t.Blurred.Base = t.Blurred.Base.
		UnsetBorderStyle().
		UnsetBorderForeground().
		BorderTop(false).
		BorderRight(false).
		BorderBottom(false).
		BorderLeft(false).
		Padding(0, 0).
		Margin(0)
	t.Blurred.Card = t.Blurred.Base
	t.Blurred.NextIndicator = lipgloss.NewStyle()
	t.Blurred.PrevIndicator = lipgloss.NewStyle()

	t.Group.Title = t.Focused.Title
	t.Group.Description = t.Focused.Description
	return t
}

func wizardStatusInfo(message string) string {
	trimmed := strings.TrimSpace(message)
	if trimmed == "" {
		return ""
	}
	return "Info: " + trimmed
}

func wizardStatusError(message string) string {
	trimmed := strings.TrimSpace(message)
	if trimmed == "" {
		return ""
	}
	if strings.HasPrefix(trimmed, "Error: ") {
		return trimmed
	}
	return "Error: " + trimmed
}

// wizardPeerLabel formats a Peer for use inside a narrow wizard list.
// The wizardLabelWidth constant determines how aggressively long names
// are truncated so the box stays readable.
func wizardPeerLabel(peer network.Peer) string {
	const labelLimit = wizardLabelWidth - 2
	name := safePeerLabel(peer.Username)
	suffix := fmt.Sprintf(" (%s)", peer.IP)
	if len([]rune(suffix)) >= labelLimit {
		return truncateRunes(peer.IP, labelLimit)
	}
	nameLimit := labelLimit - len([]rune(suffix))
	return truncateRunes(name, nameLimit) + suffix
}
