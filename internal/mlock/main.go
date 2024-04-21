package mlock

func Mlock(b []byte) error {
  return mlock(b)
}
