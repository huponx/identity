package service

import (
	"bytes"
	"encoding/base64"
	"image"
	"image/jpeg"
	"image/png"

	"github.com/huponx/gocommon/apperror"
	"golang.org/x/image/webp"
)

// Limits of a stored picture. The admin UI resizes to 256x256 before it uploads (a few tens of
// KiB); identity checks again because it never trusts the browser.
const (
	maxAvatarBytes = 64 << 10
	maxAvatarSide  = 512
)

// checkAvatar validates an encoded picture: allowed media type, small, and really an image of
// that type with sane dimensions.
func checkAvatar(data []byte, mime string) error {
	if len(data) > maxAvatarBytes {
		return apperror.InvalidArgument("the picture is larger than 64 KiB").WithReason("avatar_too_large")
	}
	var cfg image.Config
	var err error
	switch mime {
	case "image/png":
		cfg, err = png.DecodeConfig(bytes.NewReader(data))
	case "image/jpeg":
		cfg, err = jpeg.DecodeConfig(bytes.NewReader(data))
	case "image/webp":
		cfg, err = webp.DecodeConfig(bytes.NewReader(data))
	default:
		return apperror.InvalidArgument("mime_type must be image/png, image/jpeg or image/webp").WithReason("avatar_mime_type")
	}
	if err != nil {
		return apperror.InvalidArgument("the picture is not a valid "+mime).WithReason("avatar_invalid", "mime_type", mime)
	}
	if cfg.Width < 1 || cfg.Height < 1 || cfg.Width > maxAvatarSide || cfg.Height > maxAvatarSide {
		return apperror.InvalidArgument("the picture must be at most 512x512").WithReason("avatar_dimensions")
	}
	return nil
}

// avatarURI is the data URI of a picture (the web UI shows it in an img element).
func avatarURI(data []byte, mime string) string {
	return "data:" + mime + ";base64," + base64.StdEncoding.EncodeToString(data)
}
