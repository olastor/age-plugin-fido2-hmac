// +build dragonfly freebsd linux openbsd solaris

package mlock

import (
	"golang.org/x/sys/unix"
)

func mlock (b []byte) error {
  return unix.Mlock(b)
}
