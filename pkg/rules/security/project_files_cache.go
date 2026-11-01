package security

// RootFilesOnlyProjectFiles declares that ErrorDetailResponseRule reads only the root files it is given.
func (*ErrorDetailResponseRule) RootFilesOnlyProjectFiles() {}

// RootFilesOnlyProjectFiles declares that HeaderMultipleWritersRule reads only the root files it is given.
func (*HeaderMultipleWritersRule) RootFilesOnlyProjectFiles() {}

// RootFilesOnlyProjectFiles declares that IDEncodesDataRule reads only the root files it is given.
func (*IDEncodesDataRule) RootFilesOnlyProjectFiles() {}

// RootFilesOnlyProjectFiles declares that MuxAPIDefaultNotFoundRule reads only the root files it is given.
func (*MuxAPIDefaultNotFoundRule) RootFilesOnlyProjectFiles() {}
