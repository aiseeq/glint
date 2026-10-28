package patterntest

const MuxStub = `package mux

import "net/http"

type Router struct{}
type Route struct{}
type MatcherFunc func(*http.Request, *RouteMatch) bool
type RouteMatch struct{}

func NewRouter() *Router { return &Router{} }

func (r *Router) Handle(path string, h http.Handler) *Route                    { return &Route{} }
func (r *Router) HandleFunc(path string, f func(http.ResponseWriter, *http.Request)) *Route { return &Route{} }
func (r *Router) Path(tpl string) *Route                                         { return &Route{} }
func (r *Router) PathPrefix(tpl string) *Route                                   { return &Route{} }
func (r *Router) Methods(methods ...string) *Route                              { return &Route{} }
func (r *Router) ServeHTTP(w http.ResponseWriter, req *http.Request)             {}

func (r *Route) Handler(h http.Handler) *Route                                  { return r }
func (r *Route) HandlerFunc(f func(http.ResponseWriter, *http.Request)) *Route  { return r }
func (r *Route) Methods(methods ...string) *Route                               { return r }
func (r *Route) Path(tpl string) *Route                                         { return r }
func (r *Route) PathPrefix(tpl string) *Route                                   { return r }
func (r *Route) Headers(pairs ...string) *Route                                 { return r }
func (r *Route) MatcherFunc(f MatcherFunc) *Route                               { return r }
func (r *Route) Subrouter() *Router                                             { return &Router{} }
`
