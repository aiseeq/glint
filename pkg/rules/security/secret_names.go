package security

import "strings"

// Credential names by kind, as regexp alternatives matched case-insensitively.
// The security rules that recognize a credential by the name it is stored or
// sent under compose their patterns from these lists, so a new spelling is
// added in one place.
var (
	passwordNames    = []string{`password`, `passwd`, `pwd`}
	apiKeyNames      = []string{`api[-_]?key`, `apikey`}
	apiSecretNames   = []string{`api[-_]?secret`}
	tokenNames       = []string{`access[-_]?token`, `auth[-_]?token`, `authz[-_]?token`, `refresh[-_]?token`}
	bareTokenNames   = []string{`token`}
	secretNames      = []string{`secret`, `private[-_]?key`}
	oneTimeCodeNames = []string{`otp`, `otp[-_]?code`}
)

// nameAlternation joins name lists into one non-capturing regexp group.
func nameAlternation(lists ...[]string) string {
	var names []string
	for _, list := range lists {
		names = append(names, list...)
	}
	return `(?:` + strings.Join(names, `|`) + `)`
}
