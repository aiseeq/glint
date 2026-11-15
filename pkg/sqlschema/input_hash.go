package sqlschema

// InputsHash identifies the migration bytes used by LoadCached for this root,
// directory list and respectGitignore. The schema and its key are loaded
// together once.
func InputsHash(root string, dirs []string, respectGitignore bool, skipDirs ...string) (string, error) {
	_, inputs, err := loadCached(root, dirs, respectGitignore, skipDirs...)
	return inputs, err
}
