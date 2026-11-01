package errrules

// RootFilesOnlyProjectFiles declares that AggregateSkipsFailedPartRule reads only the root files it is given.
func (*AggregateSkipsFailedPartRule) RootFilesOnlyProjectFiles() {}

// RootFilesOnlyProjectFiles declares that ErrVariableHoldsNonErrorRule reads only the root files it is given.
func (*ErrVariableHoldsNonErrorRule) RootFilesOnlyProjectFiles() {}

// RootFilesOnlyProjectFiles declares that ErrorStringRule reads only the root files it is given.
func (*ErrorStringRule) RootFilesOnlyProjectFiles() {}
