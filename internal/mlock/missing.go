// +build android darwin nacl netbsd plan9 windows

package mlock

func mlock(b []byte) error {
  return nil
}
