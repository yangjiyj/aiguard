package modelaccess

import "errors"

var ErrKeyModelUnauthorized = errors.New("key model is not authorized for user")

// Empty means inheritance. Nonempty names must be within the live user's grants.
func NormalizeKeyAllowlist(names []string, access *Access) ([]string, error) {
	policy, err := Normalize(Policy{Mode: Allowlist, ModelNames: names})
	if err != nil {
		return nil, err
	}
	for _, name := range policy.ModelNames {
		if name == "*" || access == nil || !access.Allows(name) {
			return nil, ErrKeyModelUnauthorized
		}
	}
	return policy.ModelNames, nil
}
