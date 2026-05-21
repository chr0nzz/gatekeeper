package gatekeeper

import "embed"

//go:embed web/templates web/static
var Assets embed.FS
