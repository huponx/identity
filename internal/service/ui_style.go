package service

import (
	"context"
	"encoding/json"

	"github.com/huponx/gocommon/apperror"
	"github.com/huponx/identity/internal/store"
	identityv1 "github.com/huponx/protogen/go/identity/v1"
)

// DefaultUIStyle is the look of the web apps until an administrator picks another.
const DefaultUIStyle = "saas"

// uiStyles are the values of the system-wide look of the web apps.
var uiStyles = map[string]bool{"saas": true, "glass": true, "mono": true}

// DefaultUIPalette is the colour set of every look until an administrator picks another.
const DefaultUIPalette = "aurora"

// uiPalettes are the colour sets an administrator can pick for a look (the same six for every look).
var uiPalettes = map[string]bool{"aurora": true, "ocean": true, "sunset": true, "mint": true, "rose": true, "graphite": true}

// palettesOf is the palette of every look: the stored one, or the default when missing or unknown.
func palettesOf(stored map[string]string) map[string]string {
	out := make(map[string]string, len(uiStyles))
	for style := range uiStyles {
		out[style] = DefaultUIPalette
		if v := stored[style]; uiPalettes[v] {
			out[style] = v
		}
	}
	return out
}

func (s *Service) GetUIStyle(ctx context.Context, _ *identityv1.GetUIStyleRequest) (*identityv1.GetUIStyleResponse, error) {
	v, err := s.Store.UIStyle(ctx, DefaultUIStyle)
	if err != nil {
		return nil, toErr(err)
	}
	if !uiStyles[v] {
		v = DefaultUIStyle
	}
	stored, err := s.Store.UIPalettes(ctx)
	if err != nil {
		return nil, toErr(err)
	}
	return &identityv1.GetUIStyleResponse{UiStyle: v, UiPalettes: palettesOf(stored)}, nil
}

func (s *Service) SetUIStyle(ctx context.Context, req *identityv1.SetUIStyleRequest) (*identityv1.SetUIStyleResponse, error) {
	v := req.GetUiStyle()
	if !uiStyles[v] {
		return nil, apperror.InvalidArgument("ui_style must be saas, glass or mono").WithReason("ui_style_invalid")
	}
	for style, p := range req.GetUiPalettes() {
		if !uiStyles[style] {
			return nil, apperror.InvalidArgument("ui_palettes keys must be saas, glass or mono").WithReason("ui_palettes_keys_invalid")
		}
		if !uiPalettes[p] {
			return nil, apperror.InvalidArgument("ui_palettes values must be aurora, ocean, sunset, mint, rose or graphite").WithReason("ui_palettes_values_invalid")
		}
	}
	stored, err := s.Store.UIPalettes(ctx)
	if err != nil {
		return nil, toErr(err)
	}
	merged := palettesOf(stored)
	for style, p := range req.GetUiPalettes() {
		merged[style] = p
	}
	rawStyle, _ := json.Marshal(v)
	rawPalettes, _ := json.Marshal(merged)
	if err := s.Store.PutSystemSettings(ctx, map[string]json.RawMessage{store.UIStyleKey: rawStyle, store.UIPalettesKey: rawPalettes}); err != nil {
		return nil, toErr(err)
	}
	return &identityv1.SetUIStyleResponse{UiStyle: v, UiPalettes: merged}, nil
}
