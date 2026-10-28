package patternkit

// lockMethods and unlockMethods are the calls that open and close a critical
// section on sync.Mutex and sync.RWMutex.
var (
	LockMethods     = map[string]string{"Lock": "Unlock", "RLock": "RUnlock"}
	LockMethodNames = map[string]bool{"Lock": true, "RLock": true}
	UnlockMethods   = map[string]bool{"Unlock": true, "RUnlock": true}
)
