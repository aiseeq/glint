package helpers

// NetHTTPSendFuncs are the net/http package functions that send a request
// through http.DefaultClient; *http.Client has methods of the same names, plus
// Do.
var NetHTTPSendFuncs = map[string]bool{"Get": true, "Head": true, "Post": true, "PostForm": true}

// NetHTTPRequestFuncs are the net/http entry points that put a request on the
// wire or build one: the send functions and the request constructors.
var NetHTTPRequestFuncs = map[string]bool{
	"Get": true, "Post": true, "Head": true, "PostForm": true,
	"NewRequest": true, "NewRequestWithContext": true,
}
