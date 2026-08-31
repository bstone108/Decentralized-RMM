// Package consolegui is the separately deployable native GUI console.
//
// It is not a TUI and not a web console. OS adapters (Win32, X11, Aqua) are
// CGO-free so Linux CI can cross-compile rmm-console for Windows, Linux, and
// macOS. The control plane prefers a local trusted agent mesh, authorizes
// management intents before delivery, and never applies endpoint-management
// work on the console process itself.
package consolegui
