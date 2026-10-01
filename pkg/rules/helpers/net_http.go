package helpers

// NetHTTPSendFuncs are the net/http package functions that send a request
// through http.DefaultClient; *http.Client has methods of the same names, plus
// Do.
var NetHTTPSendFuncs = map[string]bool{"Get": true, "Head": true, "Post": true, "PostForm": true}
