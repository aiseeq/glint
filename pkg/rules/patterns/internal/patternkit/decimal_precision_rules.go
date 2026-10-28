package patternkit

// halfUpMethods and downMethods are the decimal methods that round half up
// and toward the floor, with their places as the first argument.
var (
	HalfUpMethods = map[string]bool{"StringFixed": true, "Round": true}
	DownMethods   = map[string]bool{"RoundFloor": true, "Truncate": true, "RoundDown": true}
)
