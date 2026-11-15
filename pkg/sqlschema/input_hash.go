package sqlschema

// InputsHash identifies the migration bytes used by LoadCached for this root,
// directory list and respectGitignore. The schema and its key are loaded
// together once.
func InputsHash(root string, dirs []string, respectGitignore bool) (string, error) {
	_, inputs, err := loadCached(root, dirs, respectGitignore)
	return inputs, err
}
