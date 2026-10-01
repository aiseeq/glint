package helpers

// EncodeFuncs name the calls that turn a value into bytes - json.Marshal,
// json.MarshalIndent, (*json.Encoder).Encode and their counterparts in other
// codecs - and read every exported field of what they are given.
var EncodeFuncs = []string{"Marshal", "MarshalIndent", "Encode"}
