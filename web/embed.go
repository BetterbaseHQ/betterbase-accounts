package web

import (
	"embed"
	"io/fs"
)

//go:embed all:dist
var content embed.FS

// DistFS returns embedded static files rooted at dist/.
func DistFS() (fs.FS, error) {
	return fs.Sub(content, "dist")
}
