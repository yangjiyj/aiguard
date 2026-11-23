package identitybinding

import (
	"context"
	"errors"
	"github.com/yangjiyj/aiguard/apps/control-plane/internal/roles"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
)

const (
	ModeAutomatic  = "automatic"
	ModeManual     = "manual"
	ModeUnassigned = "unassigned"
	ModeEmergency  = "emergency"
	ModeConflict   = "conflict"

	assignmentSourceAdmin = "admin"

	ActorPortalUserSync = "machine:portal-user-sync"
)

var (
	ErrNotFound        = errors.New("identity binding object not found")
	ErrConflict        = errors.New("identity binding conflict")
	ErrInvalidIdentity = errors.New("invalid external identity")
)

type ExternalIdentity struct {
	TenantID        string
	Issuer          string
	SourceID        string
	SourceType      string
	ExternalSubject string
	Username        string
	Email           string
	Departments     []string
	OUs             []string
	MemberOf        []string
	Groups          []string
}

type Resolution struct {
	UserID        string
	DepartmentID  string
	Mode          string
	ChatAllowed   bool
	PortalAllowed bool
	Changed       bool
	// DepartmentVersion is the monotonic users.department_version revision.
	// Zero is fail-closed and must not be reused for versioned authorization.
	DepartmentVersion int64
}

type Service interface {
	BindAndResolve(ctx context.Context, identity ExternalIdentity) (Resolution, error)
	AssignManually(ctx context.Context, tenantID, userID, departmentID, actorID string) error
	AssignManyManually(ctx context.Context, tenantID string, userIDs []string, departmentID, role, actorID string) error
	SetAutomatic(ctx context.Context, tenantID, userID, actorID string) error
	Unassign(ctx context.Context, tenantID, userID, actorID string) error
}

type UserIdentityLink struct {
	ID              string
	TenantID        string
	UserID          string
	Issuer          string
	SourceID        string
	SourceType      string
	ExternalSubject string
}

type DepartmentMapping struct {
	ID           string
	TenantID     string
	SourceType   string
	SourceID     string
	MatchType    string
	MatchValue   string
	DepartmentID string
	Priority     int
	Enabled      bool
}

type Department struct {
	ID           string
	TenantID     string
	IsUnassigned bool
}

type User struct {
	ID               string
	TenantID         string
	Username         string
	Email            string
	Role             string
	Status           string
	DepartmentID     string
	AssignmentMode   string
	AssignmentSource string
	AssignmentRuleID string
	// DepartmentResolvedAt remains the audit and display timestamp.
	// DepartmentVersion is the independent authorization revision.
	DepartmentResolvedAt time.Time
	DepartmentVersion    int64
}

type Assignment struct {
	DepartmentID string
	Mode         string
	Source       string
	RuleID       string
}

type DepartmentChangeEvent struct {
	EventID         string
	TenantID        string
	UserID          string
	OldDepartmentID string
	NewDepartmentID string
	OldRole         string
	NewRole         string
	SourceID        string
	RuleID          string
	ActorID         string
}

type Transaction interface {
	GetLink(ctx context.Context, identity ExternalIdentity) (*UserIdentityLink, error)
	CreateUser(ctx context.Context, user User) error
	CreateLinkOrGet(ctx context.Context, link UserIdentityLink) (winner UserIdentityLink, created bool, err error)
	DeleteCandidateUser(ctx context.Context, tenantID, userID string) error
	GetUser(ctx context.Context, tenantID, userID string) (*User, error)
	FindMappings(ctx context.Context, identity ExternalIdentity) ([]DepartmentMapping, error)
	GetUnassignedDepartment(ctx context.Context, tenantID string) (*Department, error)
	GetDepartment(ctx context.Context, tenantID, departmentID string) (*Department, error)
	UpdateAssignment(ctx context.Context, tenantID, userID string, assignment Assignment) error
	UpdatePlatformRole(ctx context.Context, tenantID, userID, role string) error
	ReplaceTenantPermissionGrant(ctx context.Context, tenantID, userID, role, actorID string) error
	UpdateDepartmentRole(ctx context.Context, tenantID, userID, departmentID, role string) (oldRole string, changed bool, err error)
	RecordDepartmentChange(ctx context.Context, event DepartmentChangeEvent) error
}

type Store interface {
	InTransaction(ctx context.Context, fn func(Transaction) error) error
}

type BindingService struct {
	store Store
}

func NewService(store Store) *BindingService {
	return &BindingService{store: store}
}

type desiredAssignment struct {
	assignment Assignment
	resultMode string
}

func (s *BindingService) BindAndResolve(ctx context.Context, identity ExternalIdentity) (Resolution, error) {
	if err := validateIdentityBounds(identity); err != nil {
		return Resolution{}, err
	}
	identity = normalizeIdentity(identity)
	if err := validateIdentity(identity); err != nil {
		return Resolution{}, err
	}

	var resolution Resolution
	err := s.store.InTransaction(ctx, func(tx Transaction) error {
		link, err := tx.GetLink(ctx, identity)
		if err != nil {
			return err
		}
		if link != nil {
			resolution, _, err = s.resolveLinkedUser(ctx, tx, identity, *link)
			return err
		}

		desired, err := resolveDesiredAssignment(ctx, tx, identity)
		if err != nil {
			return err
		}
		candidate := User{
			ID:               "user_" + uuid.NewString(),
			TenantID:         identity.TenantID,
			Username:         identity.Username,
			Email:            identity.Email,
			Role:             "chat_user",
			Status:           "active",
			DepartmentID:     desired.assignment.DepartmentID,
			AssignmentMode:   desired.assignment.Mode,
			AssignmentSource: desired.assignment.Source,
			AssignmentRuleID: desired.assignment.RuleID,
		}
		if err := tx.CreateUser(ctx, candidate); err != nil {
			return err
		}
		proposed := UserIdentityLink{
			ID:              "uil_" + uuid.NewString(),
			TenantID:        identity.TenantID,
			UserID:          candidate.ID,
			Issuer:          identity.Issuer,
			SourceID:        identity.SourceID,
			SourceType:      identity.SourceType,
			ExternalSubject: identity.ExternalSubject,
		}
		winner, created, err := tx.CreateLinkOrGet(ctx, proposed)
		if err != nil {
			return err
		}
		if !created {
			if err := tx.DeleteCandidateUser(ctx, identity.TenantID, candidate.ID); err != nil {
				return err
			}
			resolution, _, err = s.resolveLinkedUser(ctx, tx, identity, winner)
			return err
		}

		invalidationEventID := "identity-cache-" + uuid.NewString()
		event := DepartmentChangeEvent{
			EventID:         invalidationEventID,
			TenantID:        identity.TenantID,
			UserID:          candidate.ID,
			NewDepartmentID: candidate.DepartmentID,
			SourceID:        identity.SourceID,
			RuleID:          candidate.AssignmentRuleID,
		}
		if err := tx.RecordDepartmentChange(ctx, event); err != nil {
			return err
		}
		persistedUser, err := tx.GetUser(ctx, identity.TenantID, candidate.ID)
		if err != nil {
			return err
		}
		if persistedUser == nil {
			return ErrNotFound
		}
		resolution = Resolution{
			UserID: candidate.ID, DepartmentID: candidate.DepartmentID,
			Mode: desired.resultMode, ChatAllowed: true, PortalAllowed: canEnterPersonalPortal(candidate.Role, candidate.Status, candidate.AssignmentMode), Changed: true,
			DepartmentVersion: persistedUser.DepartmentVersion,
		}
		return nil
	})
	if err != nil {
		return Resolution{}, err
	}
	return resolution, nil
}

func (s *BindingService) resolveLinkedUser(
	ctx context.Context,
	tx Transaction,
	identity ExternalIdentity,
	link UserIdentityLink,
) (Resolution, string, error) {
	if link.TenantID != identity.TenantID {
		return Resolution{}, "", ErrNotFound
	}
	user, err := tx.GetUser(ctx, identity.TenantID, link.UserID)
	if err != nil {
		return Resolution{}, "", err
	}
	if user == nil {
		return Resolution{}, "", ErrNotFound
	}
	if user.AssignmentMode == ModeEmergency {
		return Resolution{
			UserID: user.ID, DepartmentID: user.DepartmentID,
			Mode: ModeEmergency, ChatAllowed: false, PortalAllowed: canEnterPersonalPortal(user.Role, user.Status, user.AssignmentMode),
			DepartmentVersion: user.DepartmentVersion,
		}, "", nil
	}
	if user.AssignmentMode == ModeManual {
		return Resolution{
			UserID: user.ID, DepartmentID: user.DepartmentID,
			Mode: ModeManual, ChatAllowed: true, PortalAllowed: canEnterPersonalPortal(user.Role, user.Status, user.AssignmentMode),
			DepartmentVersion: user.DepartmentVersion,
		}, "", nil
	}

	desired, err := resolveDesiredAssignment(ctx, tx, identity)
	if err != nil {
		return Resolution{}, "", err
	}
	changed := user.DepartmentID != desired.assignment.DepartmentID ||
		user.AssignmentMode != desired.assignment.Mode ||
		user.AssignmentSource != desired.assignment.Source ||
		user.AssignmentRuleID != desired.assignment.RuleID
	departmentVersion := user.DepartmentVersion
	eventID := ""
	if changed {
		if err := tx.UpdateAssignment(ctx, identity.TenantID, user.ID, desired.assignment); err != nil {
			return Resolution{}, "", err
		}
		updatedUser, err := tx.GetUser(ctx, identity.TenantID, user.ID)
		if err != nil {
			return Resolution{}, "", err
		}
		if updatedUser == nil {
			return Resolution{}, "", ErrNotFound
		}
		departmentVersion = updatedUser.DepartmentVersion
		eventID = "identity-cache-" + uuid.NewString()
		if err := tx.RecordDepartmentChange(ctx, DepartmentChangeEvent{
			EventID: eventID, TenantID: identity.TenantID, UserID: user.ID,
			OldDepartmentID: user.DepartmentID, NewDepartmentID: desired.assignment.DepartmentID,
			SourceID: identity.SourceID, RuleID: desired.assignment.RuleID,
		}); err != nil {
			return Resolution{}, "", err
		}
	}
	return Resolution{
		UserID: user.ID, DepartmentID: desired.assignment.DepartmentID,
		Mode: desired.resultMode, ChatAllowed: true, PortalAllowed: canEnterPersonalPortal(user.Role, user.Status, user.AssignmentMode), Changed: changed,
		// changed 时 department_resolved_at 已被 UpdateAssignment 刷新到 NOW；
		// 未变时沿用 user 快照。门户据此判定会话是否需要刷新授权。
		DepartmentVersion: departmentVersion,
	}, eventID, nil
}

func resolveDesiredAssignment(ctx context.Context, tx Transaction, identity ExternalIdentity) (desiredAssignment, error) {
	if identity.SourceType != "local" {
		mappings, err := tx.FindMappings(ctx, identity)
		if err != nil {
			return desiredAssignment{}, err
		}
		mappings = preferHighestPriorityMappings(preferExactMappings(mappings, identity.SourceID))
		if len(mappings) > 0 {
			departments := make(map[string]struct{})
			for _, mapping := range mappings {
				departments[mapping.DepartmentID] = struct{}{}
			}
			if len(departments) == 1 {
				return desiredAssignment{
					assignment: Assignment{
						DepartmentID: mappings[0].DepartmentID,
						Mode:         ModeAutomatic, Source: identity.SourceType, RuleID: mappings[0].ID,
					},
					resultMode: ModeAutomatic,
				}, nil
			}
			unassigned, err := requiredUnassignedDepartment(ctx, tx, identity.TenantID)
			if err != nil {
				return desiredAssignment{}, err
			}
			return desiredAssignment{
				assignment: Assignment{
					DepartmentID: unassigned.ID, Mode: ModeUnassigned,
					Source: identity.SourceType, RuleID: mappings[0].ID,
				},
				resultMode: ModeConflict,
			}, nil
		}
	}

	unassigned, err := requiredUnassignedDepartment(ctx, tx, identity.TenantID)
	if err != nil {
		return desiredAssignment{}, err
	}
	return desiredAssignment{
		assignment: Assignment{
			DepartmentID: unassigned.ID, Mode: ModeUnassigned, Source: identity.SourceType,
		},
		resultMode: ModeUnassigned,
	}, nil
}

func preferExactMappings(mappings []DepartmentMapping, sourceID string) []DepartmentMapping {
	sort.SliceStable(mappings, func(i, j int) bool {
		leftExact := sourceID != "" && mappings[i].SourceID == sourceID
		rightExact := sourceID != "" && mappings[j].SourceID == sourceID
		if leftExact != rightExact {
			return leftExact
		}
		if mappings[i].Priority != mappings[j].Priority {
			return mappings[i].Priority < mappings[j].Priority
		}
		return mappings[i].ID < mappings[j].ID
	})
	hasExact := false
	for _, mapping := range mappings {
		if sourceID != "" && mapping.SourceID == sourceID {
			hasExact = true
			break
		}
	}
	if !hasExact {
		return mappings
	}
	exact := mappings[:0]
	for _, mapping := range mappings {
		if mapping.SourceID == sourceID {
			exact = append(exact, mapping)
		}
	}
	return exact
}

func preferHighestPriorityMappings(mappings []DepartmentMapping) []DepartmentMapping {
	if len(mappings) == 0 {
		return mappings
	}
	sort.SliceStable(mappings, func(i, j int) bool {
		if mappings[i].Priority != mappings[j].Priority {
			return mappings[i].Priority < mappings[j].Priority
		}
		return mappings[i].ID < mappings[j].ID
	})
	priority := mappings[0].Priority
	end := 1
	for end < len(mappings) && mappings[end].Priority == priority {
		end++
	}
	return mappings[:end]
}

func requiredUnassignedDepartment(ctx context.Context, tx Transaction, tenantID string) (*Department, error) {
	department, err := tx.GetUnassignedDepartment(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	if department == nil {
		return nil, ErrNotFound
	}
	return department, nil
}

func (s *BindingService) AssignManually(ctx context.Context, tenantID, userID, departmentID, actorID string) error {
	tenantID = strings.TrimSpace(tenantID)
	userID = strings.TrimSpace(userID)
	departmentID = strings.TrimSpace(departmentID)
	actorID = strings.TrimSpace(actorID)
	if tenantID == "" || userID == "" || departmentID == "" || actorID == "" {
		return ErrNotFound
	}
	err := s.store.InTransaction(ctx, func(tx Transaction) error {
		user, err := tx.GetUser(ctx, tenantID, userID)
		if err != nil {
			return err
		}
		if user == nil {
			return ErrNotFound
		}
		if user.AssignmentMode == ModeEmergency {
			return ErrConflict
		}
		department, err := tx.GetDepartment(ctx, tenantID, departmentID)
		if err != nil {
			return err
		}
		if department == nil || department.IsUnassigned {
			return ErrNotFound
		}
		if user.DepartmentID == departmentID && user.AssignmentMode == ModeManual {
			return nil
		}
		assignment := Assignment{DepartmentID: departmentID, Mode: ModeManual, Source: assignmentSourceAdmin}
		if err := tx.UpdateAssignment(ctx, tenantID, userID, assignment); err != nil {
			return err
		}
		eventID := "identity-cache-" + uuid.NewString()
		return tx.RecordDepartmentChange(ctx, DepartmentChangeEvent{
			EventID: eventID, TenantID: tenantID, UserID: userID,
			OldDepartmentID: user.DepartmentID, NewDepartmentID: departmentID,
			SourceID: assignmentSourceAdmin, ActorID: actorID,
		})
	})
	if err != nil {
		return err
	}
	return nil
}

func (s *BindingService) TransitionPlatformRole(
	ctx context.Context,
	tenantID, userID, role, departmentID, actorID string,
) error {
	tenantID = strings.TrimSpace(tenantID)
	userID = strings.TrimSpace(userID)
	role = strings.TrimSpace(role)
	departmentID = strings.TrimSpace(departmentID)
	actorID = strings.TrimSpace(actorID)
	if tenantID == "" || userID == "" || role == "" || actorID == "" {
		return ErrNotFound
	}

	emergency := role == "platform_admin"
	if emergency && departmentID != "" {
		return ErrConflict
	}
	if !emergency && departmentID == "" {
		return ErrNotFound
	}

	return s.store.InTransaction(ctx, func(tx Transaction) error {
		user, err := tx.GetUser(ctx, tenantID, userID)
		if err != nil {
			return err
		}
		if user == nil {
			return ErrNotFound
		}

		assignment := Assignment{
			Mode: ModeEmergency, Source: assignmentSourceAdmin,
		}
		if !emergency {
			department, err := tx.GetDepartment(ctx, tenantID, departmentID)
			if err != nil {
				return err
			}
			if department == nil || department.IsUnassigned {
				return ErrNotFound
			}
			assignment.DepartmentID = departmentID
			assignment.Mode = ModeManual
		}

		assignmentChanged := user.DepartmentID != assignment.DepartmentID ||
			user.AssignmentMode != assignment.Mode ||
			user.AssignmentSource != assignment.Source ||
			user.AssignmentRuleID != ""
		roleChanged := user.Role != role
		if !assignmentChanged && !roleChanged {
			return nil
		}
		if assignmentChanged {
			if err := tx.UpdateAssignment(ctx, tenantID, userID, assignment); err != nil {
				return err
			}
		}
		if roleChanged {
			if err := tx.UpdatePlatformRole(ctx, tenantID, userID, role); err != nil {
				return err
			}
			if err := tx.ReplaceTenantPermissionGrant(ctx, tenantID, userID, role, actorID); err != nil {
				return err
			}
		}
		return tx.RecordDepartmentChange(ctx, DepartmentChangeEvent{
			EventID:         "identity-cache-" + uuid.NewString(),
			TenantID:        tenantID,
			UserID:          userID,
			OldDepartmentID: user.DepartmentID,
			NewDepartmentID: assignment.DepartmentID,
			OldRole:         user.Role,
			NewRole:         role,
			SourceID:        assignmentSourceAdmin,
			ActorID:         actorID,
		})
	})
}

func (s *BindingService) AssignManyManually(
	ctx context.Context,
	tenantID string,
	userIDs []string,
	departmentID, role, actorID string,
) error {
	tenantID = strings.TrimSpace(tenantID)
	departmentID = strings.TrimSpace(departmentID)
	role = strings.ToLower(strings.TrimSpace(role))
	actorID = strings.TrimSpace(actorID)
	if tenantID == "" || departmentID == "" || actorID == "" || len(userIDs) == 0 {
		return ErrNotFound
	}
	switch role {
	case "owner", "member", "viewer":
	default:
		return ErrConflict
	}
	normalizedUserIDs := make([]string, 0, len(userIDs))
	seen := make(map[string]struct{}, len(userIDs))
	for _, userID := range userIDs {
		userID = strings.TrimSpace(userID)
		if userID == "" {
			return ErrNotFound
		}
		if _, ok := seen[userID]; ok {
			continue
		}
		seen[userID] = struct{}{}
		normalizedUserIDs = append(normalizedUserIDs, userID)
	}
	sort.Strings(normalizedUserIDs)

	return s.store.InTransaction(ctx, func(tx Transaction) error {
		department, err := tx.GetDepartment(ctx, tenantID, departmentID)
		if err != nil {
			return err
		}
		if department == nil || department.IsUnassigned {
			return ErrNotFound
		}
		users := make([]User, 0, len(normalizedUserIDs))
		for _, userID := range normalizedUserIDs {
			user, err := tx.GetUser(ctx, tenantID, userID)
			if err != nil {
				return err
			}
			if user == nil {
				return ErrNotFound
			}
			if user.AssignmentMode == ModeEmergency {
				return ErrConflict
			}
			users = append(users, *user)
		}

		for _, user := range users {
			changed := user.DepartmentID != departmentID || user.AssignmentMode != ModeManual ||
				user.AssignmentSource != assignmentSourceAdmin || user.AssignmentRuleID != ""
			if changed {
				if err := tx.UpdateAssignment(ctx, tenantID, user.ID, Assignment{
					DepartmentID: departmentID,
					Mode:         ModeManual,
					Source:       assignmentSourceAdmin,
				}); err != nil {
					return err
				}
			}
			oldRole, roleChanged, err := tx.UpdateDepartmentRole(ctx, tenantID, user.ID, departmentID, role)
			if err != nil {
				return err
			}
			if changed || roleChanged {
				if err := tx.RecordDepartmentChange(ctx, DepartmentChangeEvent{
					EventID:         "identity-cache-" + uuid.NewString(),
					TenantID:        tenantID,
					UserID:          user.ID,
					OldDepartmentID: user.DepartmentID,
					NewDepartmentID: departmentID,
					OldRole:         oldRole,
					NewRole:         role,
					SourceID:        assignmentSourceAdmin,
					ActorID:         actorID,
				}); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

func (s *BindingService) SetAutomatic(ctx context.Context, tenantID, userID, actorID string) error {
	tenantID = strings.TrimSpace(tenantID)
	userID = strings.TrimSpace(userID)
	actorID = strings.TrimSpace(actorID)
	if tenantID == "" || userID == "" || actorID == "" {
		return ErrNotFound
	}
	err := s.store.InTransaction(ctx, func(tx Transaction) error {
		user, err := tx.GetUser(ctx, tenantID, userID)
		if err != nil {
			return err
		}
		if user == nil {
			return ErrNotFound
		}
		if user.AssignmentMode == ModeEmergency || user.DepartmentID == "" {
			return ErrConflict
		}
		if user.AssignmentMode == ModeAutomatic {
			return nil
		}
		assignment := Assignment{
			DepartmentID: user.DepartmentID, Mode: ModeAutomatic, Source: assignmentSourceAdmin,
		}
		if err := tx.UpdateAssignment(ctx, tenantID, userID, assignment); err != nil {
			return err
		}
		eventID := "identity-cache-" + uuid.NewString()
		return tx.RecordDepartmentChange(ctx, DepartmentChangeEvent{
			EventID: eventID, TenantID: tenantID, UserID: userID,
			OldDepartmentID: user.DepartmentID, NewDepartmentID: user.DepartmentID,
			SourceID: assignmentSourceAdmin, ActorID: actorID,
		})
	})
	if err != nil {
		return err
	}
	return nil
}

func (s *BindingService) Unassign(ctx context.Context, tenantID, userID, actorID string) error {
	tenantID = strings.TrimSpace(tenantID)
	userID = strings.TrimSpace(userID)
	actorID = strings.TrimSpace(actorID)
	if tenantID == "" || userID == "" || actorID == "" {
		return ErrNotFound
	}
	return s.store.InTransaction(ctx, func(tx Transaction) error {
		user, err := tx.GetUser(ctx, tenantID, userID)
		if err != nil {
			return err
		}
		if user == nil {
			return ErrNotFound
		}
		if user.AssignmentMode == ModeEmergency {
			return ErrConflict
		}
		unassigned, err := requiredUnassignedDepartment(ctx, tx, tenantID)
		if err != nil {
			return err
		}
		if user.DepartmentID == unassigned.ID && user.AssignmentMode == ModeUnassigned {
			return nil
		}
		assignment := Assignment{
			DepartmentID: unassigned.ID,
			Mode:         ModeUnassigned,
			Source:       assignmentSourceAdmin,
		}
		if err := tx.UpdateAssignment(ctx, tenantID, userID, assignment); err != nil {
			return err
		}
		return tx.RecordDepartmentChange(ctx, DepartmentChangeEvent{
			EventID:         "identity-cache-" + uuid.NewString(),
			TenantID:        tenantID,
			UserID:          userID,
			OldDepartmentID: user.DepartmentID,
			NewDepartmentID: unassigned.ID,
			SourceID:        assignmentSourceAdmin,
			ActorID:         actorID,
		})
	})
}

func normalizeIdentity(identity ExternalIdentity) ExternalIdentity {
	identity.TenantID = strings.TrimSpace(identity.TenantID)
	identity.Issuer = strings.TrimSpace(identity.Issuer)
	identity.SourceID = strings.TrimSpace(identity.SourceID)
	identity.SourceType = strings.ToLower(strings.TrimSpace(identity.SourceType))
	identity.ExternalSubject = strings.TrimSpace(identity.ExternalSubject)
	identity.Username = strings.TrimSpace(identity.Username)
	identity.Email = strings.TrimSpace(identity.Email)
	identity.Departments = normalizeExternalValues(identity.Departments)
	identity.OUs = normalizeExternalValues(identity.OUs)
	identity.MemberOf = normalizeExternalValues(identity.MemberOf)
	seen := make(map[string]struct{}, len(identity.Groups))
	groups := make([]string, 0, len(identity.Groups))
	for _, group := range identity.Groups {
		group = strings.TrimSpace(group)
		if group == "" {
			continue
		}
		if _, ok := seen[group]; ok {
			continue
		}
		seen[group] = struct{}{}
		groups = append(groups, group)
	}
	identity.Groups = groups
	return identity
}

func normalizeExternalValues(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	normalized := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		normalized = append(normalized, value)
	}
	return normalized
}

func validateIdentity(identity ExternalIdentity) error {
	if identity.TenantID == "" || identity.Issuer == "" || identity.ExternalSubject == "" ||
		identity.Username == "" {
		return ErrInvalidIdentity
	}
	switch identity.SourceType {
	case "local", "oidc":
	case "ldap", "ad":
		if identity.SourceID == "" || identity.SourceID != identity.Issuer {
			return ErrInvalidIdentity
		}
	default:
		return ErrInvalidIdentity
	}
	return nil
}

func validateIdentityBounds(identity ExternalIdentity) error {
	if !utf8.ValidString(identity.TenantID) ||
		!utf8.ValidString(identity.Issuer) ||
		!utf8.ValidString(identity.SourceID) ||
		!utf8.ValidString(identity.SourceType) ||
		!utf8.ValidString(identity.ExternalSubject) ||
		!utf8.ValidString(identity.Username) ||
		!utf8.ValidString(identity.Email) ||
		utf8.RuneCountInString(identity.TenantID) > 64 ||
		utf8.RuneCountInString(identity.Issuer) > 512 ||
		utf8.RuneCountInString(identity.SourceID) > 64 ||
		utf8.RuneCountInString(identity.SourceType) > 32 ||
		utf8.RuneCountInString(identity.ExternalSubject) > 512 ||
		utf8.RuneCountInString(identity.Username) > 255 ||
		utf8.RuneCountInString(identity.Email) > 255 ||
		len(identity.Groups) > 512 {
		return ErrInvalidIdentity
	}
	for _, values := range [][]string{identity.Departments, identity.OUs, identity.MemberOf} {
		if len(values) > 512 {
			return ErrInvalidIdentity
		}
		for _, value := range values {
			if !utf8.ValidString(value) || utf8.RuneCountInString(value) > 2048 {
				return ErrInvalidIdentity
			}
		}
	}
	for _, group := range identity.Groups {
		if !utf8.ValidString(group) || utf8.RuneCountInString(group) > 2048 {
			return ErrInvalidIdentity
		}
	}
	return nil
}

// TransitionTenantRole 在单事务内同步纯租户内角色变化（不涉及 emergency/
// platform_admin 边界的角色切换，例如 viewer -> tenant_admin）。
//
// 与 TransitionPlatformRole 的区别：
//   - 不切换 department assignment（用户已有所属部门，纯角色升级/降级）
//   - 不编排 Keycloak subject 启用/禁用（subject 状态保持不变）
//   - 仍走事务化路径：UpdatePlatformRole + ReplaceTenantPermissionGrant +
//     RecordDepartmentChange（audit + outbox），保证 enforce 中间件看到的
//     permission_grants 与 users.role 一致，且 cache 失效信号入队。
//
// 调用方应在 commit 成功后调 PermissionChecker.InvalidateUserCache(userID)。
func (s *BindingService) TransitionTenantRole(
	ctx context.Context,
	tenantID, userID, role, actorID string,
) error {
	tenantID = strings.TrimSpace(tenantID)
	userID = strings.TrimSpace(userID)
	role = strings.TrimSpace(role)
	actorID = strings.TrimSpace(actorID)
	if tenantID == "" || userID == "" || role == "" || actorID == "" {
		return ErrNotFound
	}
	// 仅接受非 platform_admin 的平台角色；emergency 边界走 TransitionPlatformRole。
	if role == "platform_admin" {
		return ErrConflict
	}
	return s.store.InTransaction(ctx, func(tx Transaction) error {
		user, err := tx.GetUser(ctx, tenantID, userID)
		if err != nil {
			return err
		}
		if user == nil {
			return ErrNotFound
		}
		if user.Role == role {
			return nil
		}
		// emergency 用户离开 emergency 必须指定 department，走 TransitionPlatformRole。
		if user.AssignmentMode == ModeEmergency {
			return ErrConflict
		}
		if err := tx.UpdatePlatformRole(ctx, tenantID, userID, role); err != nil {
			return err
		}
		if err := tx.ReplaceTenantPermissionGrant(ctx, tenantID, userID, role, actorID); err != nil {
			return err
		}
		return tx.RecordDepartmentChange(ctx, DepartmentChangeEvent{
			EventID:         "identity-cache-" + uuid.NewString(),
			TenantID:        tenantID,
			UserID:          userID,
			OldDepartmentID: user.DepartmentID,
			NewDepartmentID: user.DepartmentID,
			OldRole:         user.Role,
			NewRole:         role,
			SourceID:        assignmentSourceAdmin,
			ActorID:         actorID,
		})
	})
}

func canEnterPersonalPortal(role, status, assignmentMode string) bool {
	return status == "active" && roles.CanLoginPortal(role) && assignmentMode != "service"
}
