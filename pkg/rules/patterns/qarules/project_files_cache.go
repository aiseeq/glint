package qarules

// RootFilesOnlyProjectFiles declares that SkippedTestRule reads only the root files it is given.
func (*SkippedTestRule) RootFilesOnlyProjectFiles() {}

// RootFilesOnlyProjectFiles declares that SubtestFixtureCleanedEarlyRule reads only the root files it is given.
func (*SubtestFixtureCleanedEarlyRule) RootFilesOnlyProjectFiles() {}

// RootFilesOnlyProjectFiles declares that TestAuthSchemeDriftRule reads only the root files it is given.
func (*TestAuthSchemeDriftRule) RootFilesOnlyProjectFiles() {}

// RootFilesOnlyProjectFiles declares that TestDependsOnWallClockRule reads only the root files it is given.
func (*TestDependsOnWallClockRule) RootFilesOnlyProjectFiles() {}

// RootFilesOnlyProjectFiles declares that TestEmailRegistrableDomainRule reads only the root files it is given.
func (*TestEmailRegistrableDomainRule) RootFilesOnlyProjectFiles() {}

// RootFilesOnlyProjectFiles declares that TestSchemaMutationWithoutCleanupRule reads only the root files it is given.
func (*TestSchemaMutationWithoutCleanupRule) RootFilesOnlyProjectFiles() {}
