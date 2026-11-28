package useragent

import "testing"

func TestParse(t *testing.T) {
	tests := []struct {
		name string
		ua   string
		want Info
	}{
		{"chrome mac", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36", Info{"Chrome", "126", "macOS", Desktop}},
		{"edge windows", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Edg/126.0.2592.81", Info{"Edge", "126", "Windows", Desktop}},
		{"opera", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 OPR/111.0.0.0", Info{"Opera", "111", "Windows", Desktop}},
		{"firefox linux", "Mozilla/5.0 (X11; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0", Info{"Firefox", "127", "Linux", Desktop}},
		{"safari mac", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15", Info{"Safari", "17", "macOS", Desktop}},
		{"safari iphone", "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1", Info{"Safari", "17", "iOS", Mobile}},
		{"chrome iphone", "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/126.0.6478.153 Mobile/15E148 Safari/604.1", Info{"Chrome", "126", "iOS", Mobile}},
		{"firefox ipad", "Mozilla/5.0 (iPad; CPU OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/127.0 Mobile/15E148 Safari/605.1.15", Info{"Firefox", "127", "iOS", Tablet}},
		{"chrome android phone", "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Mobile Safari/537.36", Info{"Chrome", "126", "Android", Mobile}},
		{"chrome android tablet", "Mozilla/5.0 (Linux; Android 13; SM-X700) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36", Info{"Chrome", "126", "Android", Tablet}},
		{"chromeos", "Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36", Info{"Chrome", "126", "ChromeOS", Desktop}},
		{"empty", "", Info{Device: Unknown}},
		{"garbage", "curl/8.4.0 \x00\xff???", Info{Device: Unknown}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Parse(tt.ua); got != tt.want {
				t.Errorf("Parse = %+v, want %+v", got, tt.want)
			}
		})
	}
}
