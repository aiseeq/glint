package sqlschema

// InputsHash identifies the migration bytes used by LoadCached for this root
// and directory list. The schema and its key are loaded together once.
func InputsHash(root string, dirs []string) (string, error) {
	_, inputs, err := loadCached(root, dirs)
	return inputs, err
}
