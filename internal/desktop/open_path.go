package desktop

import (
	"errors"
	"os/exec"
	"runtime"
)

func openPathInFileManager(path string) error {
	if path == "" {
		return errors.New("path is empty")
	}
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", path)
	case "windows":
		cmd = exec.Command("explorer", path)
	default:
		cmd = exec.Command("xdg-open", path)
	}
	return cmd.Start()
}
