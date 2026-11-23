package handler

import (
	"net/http"
	"time"
)

func userStore(deps *Dependencies) UserStore {
	if deps.UserStore != nil {
		return deps.UserStore
	}
	return deps.UserRepo
}

func enforceMaxUsersForActiveUser(w http.ResponseWriter, r *http.Request, deps *Dependencies) bool {
	maxUsers := currentLicenseMaxUsers(r, deps)
	if maxUsers <= 0 {
		return true
	}
	users, err := userStore(deps).ListAllWithStats(r.Context())
	if err != nil {
		writeError(w, "internal_error", "failed to count active users")
		return false
	}
	active := 0
	for _, user := range users {
		if user.Status == "active" {
			active++
		}
	}
	if active >= maxUsers {
		writeErrorWithStatus(w, http.StatusPaymentRequired, "license_max_users_exceeded", "active user limit reached")
		return false
	}
	return true
}

func currentLicenseMaxUsers(r *http.Request, deps *Dependencies) int {
	if deps == nil || deps.SystemRepo == nil {
		return 0
	}
	stored, err := getLicenseSetting(r, deps, LicenseSettingKey)
	if err != nil || stored == "" {
		return 0
	}
	status := licenseStatusFromStored(r, deps, stored, "", time.Now().UTC())
	if !status.Valid {
		return 0
	}
	if status.PayloadV2 != nil {
		return status.PayloadV2.MaxUsers
	}
	if status.Payload != nil {
		return status.Payload.MaxUsers
	}
	return 0
}
