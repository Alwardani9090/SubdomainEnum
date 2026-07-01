package log

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

type Level int

const (
	LevelSilent Level = iota
	LevelNormal
	LevelVerbose
)

const (
	reset   = "\033[0m"
	bold    = "\033[1m"
	dim     = "\033[2m"
	red     = "\033[31m"
	green   = "\033[32m"
	yellow  = "\033[33m"
	blue    = "\033[34m"
	magenta = "\033[35m"
	cyan    = "\033[36m"
	white   = "\033[37m"
)

type Logger struct {
	mu        sync.Mutex
	level     Level
	noColor   bool
	start     time.Time
	sources   []SourceStat
	sourcesMu sync.Mutex
}

type SourceStat struct {
	Name     string
	Count    int
	Duration time.Duration
	Error    string
}

type Summary struct {
	DiscoveredHosts     int
	ResolvedHosts       int
	DuplicateDiscarded  int
	InvalidDiscarded    int
	WildcardDiscarded   int
	UnresolvedDiscarded int
	ValidationSkipped   bool
}

var global = &Logger{
	level: LevelNormal,
	start: time.Now(),
}

func Init(level Level, noColor bool) {
	global.mu.Lock()
	defer global.mu.Unlock()
	global.level = level
	global.noColor = noColor
	global.start = time.Now()
	global.sources = nil
}

func GetLevel() Level { return global.level }

func Banner() {
	if global.level == LevelSilent {
		return
	}
	global.mu.Lock()
	defer global.mu.Unlock()

	c := func(color, text string) string {
		if global.noColor {
			return text
		}
		return color + text + reset
	}

	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, c(bold+cyan, "   _____       __    ____                        _        ______                      "))
	fmt.Fprintln(os.Stderr, c(bold+cyan, "  / ___/__  __/ /_  / __ \\____  ____ ___  ____ _(_)___   / ____/___  __  ______ ___   "))
	fmt.Fprintln(os.Stderr, c(bold+cyan, "  \\__ \\/ / / / __ \\/ / / / __ \\/ __ `__ \\/ __ `/ / __ \\ / __/ / __ \\/ / / / __ `__ \\"))
	fmt.Fprintln(os.Stderr, c(bold+cyan, " ___/ / /_/ / /_/ / /_/ / /_/ / / / / / / /_/ / / / / // /___ / / / / /_/ / / / / / /"))
	fmt.Fprintln(os.Stderr, c(bold+cyan, "/____/\\__,_/_.___/_____/\\____/_/ /_/ /_/\\__,_/_/_/ /_/ /_____//_/ /_/\\__,_/_/ /_/ /_/ "))
	fmt.Fprintln(os.Stderr)
	fmt.Fprintf(os.Stderr, "  %s %s\n", c(dim, "Subdomain Enumeration Framework"), c(dim+yellow, "v1.0"))
	fmt.Fprintln(os.Stderr)
}

func Infof(format string, args ...any) {
	if global.level == LevelSilent {
		return
	}
	global.mu.Lock()
	defer global.mu.Unlock()
	prefix := colorize(blue, "INF")
	ts := timestamp()
	fmt.Fprintf(os.Stderr, "[%s] [%s] %s\n", ts, prefix, fmt.Sprintf(format, args...))
}

func Warnf(format string, args ...any) {
	if global.level == LevelSilent {
		return
	}
	global.mu.Lock()
	defer global.mu.Unlock()
	prefix := colorize(yellow, "WRN")
	ts := timestamp()
	fmt.Fprintf(os.Stderr, "[%s] [%s] %s\n", ts, prefix, fmt.Sprintf(format, args...))
}

func Errorf(format string, args ...any) {
	if global.level == LevelSilent {
		return
	}
	global.mu.Lock()
	defer global.mu.Unlock()
	prefix := colorize(red, "ERR")
	ts := timestamp()
	fmt.Fprintf(os.Stderr, "[%s] [%s] %s\n", ts, prefix, fmt.Sprintf(format, args...))
}

func Fatalf(format string, args ...any) {
	global.mu.Lock()
	prefix := colorize(red, "FTL")
	ts := timestamp()
	fmt.Fprintf(os.Stderr, "[%s] [%s] %s\n", ts, prefix, fmt.Sprintf(format, args...))
	global.mu.Unlock()
	os.Exit(1)
}

func Debugf(format string, args ...any) {
	if global.level < LevelVerbose {
		return
	}
	global.mu.Lock()
	defer global.mu.Unlock()
	prefix := colorize(dim, "DBG")
	ts := timestamp()
	fmt.Fprintf(os.Stderr, "[%s] [%s] %s\n", ts, prefix, fmt.Sprintf(format, args...))
}

func Resultf(format string, args ...any) {
	global.mu.Lock()
	defer global.mu.Unlock()
	fmt.Fprintf(os.Stdout, format+"\n", args...)
}

func SourceStart(name string) {
	if global.level == LevelSilent {
		return
	}
	global.mu.Lock()
	defer global.mu.Unlock()
	prefix := colorize(blue, "INF")
	tag := colorize(cyan, name)
	ts := timestamp()
	fmt.Fprintf(os.Stderr, "[%s] [%s] [%s] Searching...\n", ts, prefix, tag)
}

func SourceDone(name string, count int, duration time.Duration, err error) {
	global.sourcesMu.Lock()
	stat := SourceStat{Name: name, Count: count, Duration: duration}
	if err != nil {
		stat.Error = err.Error()
	}
	global.sources = append(global.sources, stat)
	global.sourcesMu.Unlock()

	if global.level == LevelSilent {
		return
	}

	global.mu.Lock()
	defer global.mu.Unlock()
	ts := timestamp()

	if err != nil {
		prefix := colorize(red, "ERR")
		tag := colorize(red, name)
		errStr := err.Error()
		if len(errStr) > 120 {
			errStr = errStr[:120] + "..."
		}
		fmt.Fprintf(os.Stderr, "[%s] [%s] [%s] Failed (%s): %s\n",
			ts, prefix, tag, formatDuration(duration), errStr)
	} else {
		prefix := colorize(blue, "INF")
		tag := colorize(green, name)
		fmt.Fprintf(os.Stderr, "[%s] [%s] [%s] Found %s subdomain(s) in %s\n",
			ts, prefix, tag, colorize(bold+white, fmt.Sprintf("%d", count)), formatDuration(duration))
	}
}

func ListSubdomains(subs []string) {
	if global.level < LevelVerbose || len(subs) == 0 {
		return
	}
	global.mu.Lock()
	defer global.mu.Unlock()
	for _, s := range subs {
		fmt.Fprintf(os.Stderr, "    %s\n", colorize(dim, s))
	}
}

func SourceProgress(done, total int) {
	if global.level == LevelSilent {
		return
	}
	global.mu.Lock()
	defer global.mu.Unlock()
	ts := timestamp()
	prefix := colorize(blue, "INF")
	bar := progressBar(done, total, 30)
	fmt.Fprintf(os.Stderr, "[%s] [%s] Sources: %s %d/%d\n", ts, prefix, bar, done, total)
}

func Phase(name string) {
	if global.level == LevelSilent {
		return
	}
	global.mu.Lock()
	defer global.mu.Unlock()
	ts := timestamp()
	line := strings.Repeat("─", 50)
	fmt.Fprintf(os.Stderr, "\n[%s] %s %s %s\n", ts,
		colorize(dim, line[:10]),
		colorize(bold+magenta, name),
		colorize(dim, line[:10]))
}

func Stat(key string, value any) {
	if global.level == LevelSilent {
		return
	}
	global.mu.Lock()
	defer global.mu.Unlock()
	ts := timestamp()
	prefix := colorize(blue, "INF")
	fmt.Fprintf(os.Stderr, "[%s] [%s] %-35s %s\n", ts, prefix,
		colorize(dim, key+":"), colorize(bold+white, fmt.Sprintf("%v", value)))
}

func PrintStats(summary Summary) {
	if global.level == LevelSilent {
		return
	}

	global.mu.Lock()
	defer global.mu.Unlock()

	elapsed := time.Since(global.start)
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, colorize(bold+cyan, "┌─────────────────────────────────────────────────────────────┐"))
	fmt.Fprintln(os.Stderr, colorize(bold+cyan, "│")+colorize(bold+white, "                     ENUMERATION SUMMARY                     ")+colorize(bold+cyan, "│"))
	fmt.Fprintln(os.Stderr, colorize(bold+cyan, "├──────────────────────────┬──────────┬────────┬──────────────┤"))
	fmt.Fprintf(os.Stderr, "%s%s%s%s%s%s%s%s%s\n",
		colorize(cyan, "│"), colorize(bold+white, fmt.Sprintf(" %-24s ", "Source")),
		colorize(cyan, "│"), colorize(bold+white, fmt.Sprintf(" %-8s ", "Found")),
		colorize(cyan, "│"), colorize(bold+white, fmt.Sprintf(" %-6s ", "Time")),
		colorize(cyan, "│"), colorize(bold+white, fmt.Sprintf(" %-12s ", "Status")),
		colorize(cyan, "│"))
	fmt.Fprintln(os.Stderr, colorize(bold+cyan, "├──────────────────────────┼──────────┼────────┼──────────────┤"))

	global.sourcesMu.Lock()
	for _, s := range global.sources {
		status := colorize(green, "OK")
		countStr := fmt.Sprintf("%d", s.Count)
		if s.Error != "" {
			status = colorize(red, "FAILED")
			countStr = colorize(dim, "-")
		}
		fmt.Fprintf(os.Stderr, colorize(cyan, "│")+" %-24s "+colorize(cyan, "│")+" %-8s "+
			colorize(cyan, "│")+" %-6s "+colorize(cyan, "│")+" %-12s "+colorize(cyan, "│\n"),
			s.Name, countStr, formatDuration(s.Duration), status)
	}
	global.sourcesMu.Unlock()

	fmt.Fprintln(os.Stderr, colorize(bold+cyan, "├──────────────────────────┴──────────┴────────┴──────────────┤"))
	fmt.Fprintf(os.Stderr, colorize(bold+cyan, "│")+" Discovered: %-9s Resolved: %-10s Time: %-8s "+colorize(bold+cyan, "│\n"),
		colorize(bold+green, fmt.Sprintf("%d", summary.DiscoveredHosts)),
		colorize(bold+green, fmt.Sprintf("%d", summary.ResolvedHosts)),
		colorize(bold+yellow, formatDuration(elapsed)))

	resolutionState := colorize(green, "active")
	if summary.ValidationSkipped {
		resolutionState = colorize(yellow, "skipped")
	}
	fmt.Fprintf(os.Stderr, colorize(bold+cyan, "│")+" Dropped dupes: %-6s Invalid: %-6s Wildcard: %-6s DNS-miss: %-6s "+colorize(bold+cyan, "│\n"),
		colorize(bold+yellow, fmt.Sprintf("%d", summary.DuplicateDiscarded)),
		colorize(bold+yellow, fmt.Sprintf("%d", summary.InvalidDiscarded)),
		colorize(bold+yellow, fmt.Sprintf("%d", summary.WildcardDiscarded)),
		colorize(bold+yellow, fmt.Sprintf("%d", summary.UnresolvedDiscarded)))
	fmt.Fprintf(os.Stderr, colorize(bold+cyan, "│")+" Final DNS validation: %-43s "+colorize(bold+cyan, "│\n"), resolutionState)
	fmt.Fprintln(os.Stderr, colorize(bold+cyan, "└─────────────────────────────────────────────────────────────┘"))
	fmt.Fprintln(os.Stderr)
}

func timestamp() string {
	elapsed := time.Since(global.start)
	ts := fmt.Sprintf("%02d:%02d", int(elapsed.Minutes()), int(elapsed.Seconds())%60)
	return colorize(dim, ts)
}

func colorize(color, text string) string {
	if global.noColor {
		return text
	}
	return color + text + reset
}

func formatDuration(d time.Duration) string {
	if d < time.Second {
		return fmt.Sprintf("%dms", d.Milliseconds())
	}
	if d < time.Minute {
		return fmt.Sprintf("%.1fs", d.Seconds())
	}
	return fmt.Sprintf("%dm%ds", int(d.Minutes()), int(d.Seconds())%60)
}

func progressBar(done, total, width int) string {
	if total == 0 {
		return strings.Repeat("░", width)
	}
	filled := (done * width) / total
	if filled > width {
		filled = width
	}
	bar := colorize(green, strings.Repeat("█", filled)) + colorize(dim, strings.Repeat("░", width-filled))
	return bar
}
