// Package useragent splits a User-Agent header into the few things a person recognizes a device by:
// browser, operating system and kind of device. It is a small ordered rule table, not a full parser; an
// unknown agent gives empty fields (the Device is "unknown").
package useragent

import (
	"regexp"
	"strings"
)

// Device kinds.
const (
	Desktop = "desktop"
	Mobile  = "mobile"
	Tablet  = "tablet"
	Unknown = "unknown"
)

// Info is what Parse finds.
type Info struct {
	Browser string
	Version string // the major version, "" when unknown
	OS      string
	Device  string // desktop, mobile, tablet or unknown
}

type browserRule struct {
	name string
	re   *regexp.Regexp
}

// The order matters: Edge, Opera and the iOS wrappers also say "Chrome" or "Safari" in their agent.
var browsers = []browserRule{
	{"Edge", regexp.MustCompile(`\b(?:Edg|EdgA|EdgiOS|Edge)/(\d+)`)},
	{"Opera", regexp.MustCompile(`\b(?:OPR|OPiOS)/(\d+)`)},
	{"Firefox", regexp.MustCompile(`\b(?:Firefox|FxiOS)/(\d+)`)},
	{"Chrome", regexp.MustCompile(`\b(?:Chrome|CriOS)/(\d+)`)},
	{"Safari", regexp.MustCompile(`\bVersion/(\d+)[^ ]* (?:Mobile/\S+ )?Safari/`)},
}

type osRule struct {
	name string
	re   *regexp.Regexp
}

// iPhone and iPad come before macOS (an iPad agent says "like Mac OS X"), Android before Linux.
var systems = []osRule{
	{"Windows", regexp.MustCompile(`Windows`)},
	{"iOS", regexp.MustCompile(`iPhone|iPad|iPod`)},
	{"Android", regexp.MustCompile(`Android`)},
	{"ChromeOS", regexp.MustCompile(`CrOS`)},
	{"macOS", regexp.MustCompile(`Macintosh|Mac OS X`)},
	{"Linux", regexp.MustCompile(`Linux|X11`)},
}

// Parse reads a User-Agent header.
func Parse(ua string) Info {
	info := Info{Device: Unknown}
	ua = strings.TrimSpace(ua)
	if ua == "" {
		return info
	}
	for _, b := range browsers {
		if m := b.re.FindStringSubmatch(ua); m != nil {
			info.Browser, info.Version = b.name, m[1]
			break
		}
	}
	for _, o := range systems {
		if o.re.MatchString(ua) {
			info.OS = o.name
			break
		}
	}
	switch {
	case strings.Contains(ua, "iPad"), strings.Contains(ua, "Android") && !strings.Contains(ua, "Mobile"):
		info.Device = Tablet
	case strings.Contains(ua, "iPhone"), strings.Contains(ua, "iPod"), strings.Contains(ua, "Android"):
		info.Device = Mobile
	case info.OS != "":
		info.Device = Desktop
	}
	return info
}
