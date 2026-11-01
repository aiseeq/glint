package dbrules

// RootFilesOnlyProjectFiles declares that GoFilterCopiesSQLPredicateRule reads only the root files it is given.
func (*GoFilterCopiesSQLPredicateRule) RootFilesOnlyProjectFiles() {}

// RootFilesOnlyProjectFiles declares that MigrationSessionSettingsLeakRule reads only the root files it is given.
func (*MigrationSessionSettingsLeakRule) RootFilesOnlyProjectFiles() {}

// RootFilesOnlyProjectFiles declares that SQLLiteralCopiesConstantRule reads only the root files it is given.
func (*SQLLiteralCopiesConstantRule) RootFilesOnlyProjectFiles() {}

// RootFilesOnlyProjectFiles declares that SQLSerializableNoRetryRule reads only the root files it is given.
func (*SQLSerializableNoRetryRule) RootFilesOnlyProjectFiles() {}

// RootFilesOnlyProjectFiles declares that SQLSessionTimeZoneRule reads only the root files it is given.
func (*SQLSessionTimeZoneRule) RootFilesOnlyProjectFiles() {}
