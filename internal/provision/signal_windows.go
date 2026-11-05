package provision

import "os"

// hangups returns nil on Windows, which has no SIGHUP. A nil channel never fires.
func hangups() <-chan os.Signal { return nil }
