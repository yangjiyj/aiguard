package identitybinding

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
)

type fakeStore struct {
	mu           sync.Mutex
	users        map[string]User
	links        map[string]UserIdentityLink
	departments  map[string]Department
	mappings     []DepartmentMapping
	roles        map[string]string
	grants       map[string]string
	audits       []DepartmentChangeEvent
	getUserCalls []string
	events       map[string]bool
}

func newFakeStore() *fakeStore {
	s := &fakeStore{
		users:       make(map[string]User),
		links:       make(map[string]UserIdentityLink),
		departments: make(map[string]Department),
		roles:       make(map[string]string),
		grants:      make(map[string]string),
		events:      make(map[string]bool),
	}
	s.addDepartment("tenant-a", "dept-unassigned", true)
	s.addDepartment("tenant-a", "dept-a", false)
	s.addDepartment("tenant-a", "dept-b", false)
	s.addDepartment("tenant-b", "dept-b-other", false)
	return s
}

func (s *fakeStore) addDepartment(tenantID, id string, unassigned bool) {
	s.departments[tenantID+"|"+id] = Department{ID: id, TenantID: tenantID, IsUnassigned: unassigned}
}

func (s *fakeStore) InTransaction(ctx context.Context, fn func(Transaction) error) error {
	return fn(s)
}

func stableKey(identity ExternalIdentity) string {
	return identity.TenantID + "|" + identity.Issuer + "|" + identity.SourceType + "|" + identity.ExternalSubject
}

func (s *fakeStore) GetLink(_ context.Context, identity ExternalIdentity) (*UserIdentityLink, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	link, ok := s.links[stableKey(identity)]
	if !ok {
		return nil, nil
	}
	return &link, nil
}

func (s *fakeStore) CreateUser(_ context.Context, user User) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	user.DepartmentVersion = 1000
	s.users[user.TenantID+"|"+user.ID] = user
	return nil
}

func (s *fakeStore) CreateLinkOrGet(_ context.Context, link UserIdentityLink) (UserIdentityLink, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := link.TenantID + "|" + link.Issuer + "|" + link.SourceType + "|" + link.ExternalSubject
	if winner, ok := s.links[key]; ok {
		return winner, false, nil
	}
	s.links[key] = link
	return link, true, nil
}

func (s *fakeStore) DeleteCandidateUser(_ context.Context, tenantID, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.users, tenantID+"|"+userID)
	return nil
}

func (s *fakeStore) GetUser(_ context.Context, tenantID, userID string) (*User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.getUserCalls = append(s.getUserCalls, userID)
	user, ok := s.users[tenantID+"|"+userID]
	if !ok {
		return nil, nil
	}
	return &user, nil
}

func (s *fakeStore) FindMappings(_ context.Context, identity ExternalIdentity) ([]DepartmentMapping, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	valuesByType := map[string][]string{
		"department": identity.Departments,
		"ou":         identity.OUs,
		"member_of":  identity.MemberOf,
		"groups":     identity.Groups,
	}
	var found []DepartmentMapping
	for _, mapping := range s.mappings {
		matched := false
		for _, value := range valuesByType[mapping.MatchType] {
			if value == mapping.MatchValue {
				matched = true
				break
			}
		}
		if mapping.TenantID == identity.TenantID && mapping.SourceType == identity.SourceType && mapping.Enabled &&
			matched && (mapping.SourceID == identity.SourceID || mapping.SourceID == "") {
			found = append(found, mapping)
		}
	}
	return found, nil
}

func (s *fakeStore) GetUnassignedDepartment(_ context.Context, tenantID string) (*Department, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, department := range s.departments {
		if department.TenantID == tenantID && department.IsUnassigned {
			return &department, nil
		}
	}
	return nil, nil
}

func (s *fakeStore) GetDepartment(_ context.Context, tenantID, departmentID string) (*Department, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	department, ok := s.departments[tenantID+"|"+departmentID]
	if !ok {
		return nil, nil
	}
	return &department, nil
}

func (s *fakeStore) UpdateAssignment(_ context.Context, tenantID, userID string, assignment Assignment) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := tenantID + "|" + userID
	user, ok := s.users[key]
	if !ok {
		return ErrNotFound
	}
	user.DepartmentID = assignment.DepartmentID
	user.AssignmentMode = assignment.Mode
	user.AssignmentSource = assignment.Source
	user.AssignmentRuleID = assignment.RuleID
	user.DepartmentVersion++
	s.users[key] = user
	return nil
}

func (s *fakeStore) UpdatePlatformRole(_ context.Context, tenantID, userID, role string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := tenantID + "|" + userID
	user, ok := s.users[key]
	if !ok {
		return ErrNotFound
	}
	user.Role = role
	s.users[key] = user
	return nil
}

func (s *fakeStore) ReplaceTenantPermissionGrant(_ context.Context, tenantID, userID, role, _ string) error {
	s.grants[tenantID+"|"+userID] = role
	return nil
}

func (s *fakeStore) UpdateDepartmentRole(_ context.Context, tenantID, userID, departmentID, role string) (string, bool, error) {
	key := tenantID + "|" + userID + "|" + departmentID
	oldRole, ok := s.roles[key]
	if ok && oldRole == role {
		return oldRole, false, nil
	}
	s.roles[key] = role
	return oldRole, true, nil
}

func (s *fakeStore) RecordDepartmentChange(_ context.Context, event DepartmentChangeEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.audits = append(s.audits, event)
	s.events[event.EventID] = false
	return nil
}

func (s *fakeStore) MarkInvalidationProcessed(_ context.Context, eventID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.events[eventID]; !ok {
		return ErrNotFound
	}
	s.events[eventID] = true
	return nil
}

func (s *fakeStore) addMapping(id, tenantID, sourceType, sourceID, group, departmentID string, priority int) {
	s.mappings = append(s.mappings, DepartmentMapping{
		ID: id, TenantID: tenantID, SourceType: sourceType, SourceID: sourceID,
		MatchType: "groups", MatchValue: group, DepartmentID: departmentID, Priority: priority, Enabled: true,
	})
}

type fakeInvalidator struct {
	mu         sync.Mutex
	calls      []string
	modelCalls []string
	err        error
	modelErr   error
}

func (i *fakeInvalidator) InvalidateUserCache(_ context.Context, userID string) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.calls = append(i.calls, userID)
	return i.err
}

func (i *fakeInvalidator) InvalidateUserModelAuthorizationCache(_ context.Context, userID string) error {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.modelCalls = append(i.modelCalls, userID)
	return i.modelErr
}

func testIdentity(subject, email string, groups ...string) ExternalIdentity {
	return ExternalIdentity{
		TenantID: "tenant-a", Issuer: "https://issuer.example", SourceID: "source-a",
		SourceType: "oidc", ExternalSubject: subject, Username: "alice", Email: email, Groups: groups,
	}
}

func bindService(store *fakeStore, _ *fakeInvalidator) *BindingService {
	return NewService(store)
}

func TestBindAndResolveIdempotentStableKey(t *testing.T) {
	store := newFakeStore()
	store.addMapping("rule-a", "tenant-a", "oidc", "source-a", "group-a", "dept-a", 10)
	service := bindService(store, &fakeInvalidator{})
	identity := testIdentity("subject-1", "alice@example.com", "group-a")
	first, err := service.BindAndResolve(context.Background(), identity)
	if err != nil {
		t.Fatal(err)
	}
	second, err := service.BindAndResolve(context.Background(), identity)
	if err != nil {
		t.Fatal(err)
	}
	if first.UserID == "" || second.UserID != first.UserID || second.Changed {
		t.Fatalf("first=%+v second=%+v", first, second)
	}
}

func TestBindAndResolveNewUserReturnsPersistedDepartmentVersion(t *testing.T) {
	store := newFakeStore()
	store.addMapping("rule-a", "tenant-a", "oidc", "source-a", "group-a", "dept-a", 10)

	got, err := bindService(store, &fakeInvalidator{}).BindAndResolve(
		context.Background(), testIdentity("subject-new", "new@example.com", "group-a"),
	)
	if err != nil {
		t.Fatal(err)
	}
	persisted := store.users["tenant-a|"+got.UserID].DepartmentVersion
	if persisted == 0 {
		t.Fatal("fake database must persist a non-zero department version")
	}
	if got.DepartmentVersion != persisted {
		t.Fatalf("resolution version=%v persisted version=%v", got.DepartmentVersion, persisted)
	}
}

func TestSameEmailDifferentSubjectDoesNotMerge(t *testing.T) {
	store := newFakeStore()
	service := bindService(store, &fakeInvalidator{})
	first, err := service.BindAndResolve(context.Background(), testIdentity("subject-1", "same@example.com"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := service.BindAndResolve(context.Background(), testIdentity("subject-2", "same@example.com"))
	if err != nil {
		t.Fatal(err)
	}
	if first.UserID == second.UserID {
		t.Fatalf("different stable identities merged by email into %s", first.UserID)
	}
}

func TestExactSourceMappingBeatsLegacyFallback(t *testing.T) {
	store := newFakeStore()
	store.addMapping("fallback", "tenant-a", "oidc", "", "group-a", "dept-a", 1)
	store.addMapping("exact", "tenant-a", "oidc", "source-a", "group-a", "dept-b", 100)
	got, err := bindService(store, &fakeInvalidator{}).BindAndResolve(context.Background(), testIdentity("subject", "a@example.com", "group-a"))
	if err != nil {
		t.Fatal(err)
	}
	if got.DepartmentID != "dept-b" || got.Mode != ModeAutomatic {
		t.Fatalf("resolution=%+v", got)
	}
}

func TestMultipleGroupsMappedToSameDepartmentAreNotConflict(t *testing.T) {
	store := newFakeStore()
	store.addMapping("rule-a", "tenant-a", "oidc", "source-a", "group-a", "dept-a", 10)
	store.addMapping("rule-b", "tenant-a", "oidc", "source-a", "group-b", "dept-a", 10)
	got, err := bindService(store, &fakeInvalidator{}).BindAndResolve(context.Background(), testIdentity("subject", "a@example.com", "group-a", "group-b"))
	if err != nil {
		t.Fatal(err)
	}
	if got.DepartmentID != "dept-a" || got.Mode != ModeAutomatic {
		t.Fatalf("resolution=%+v", got)
	}
}

func TestLowestPriorityNumberWinsWithinSelectedSourceScope(t *testing.T) {
	store := newFakeStore()
	store.addMapping("rule-a", "tenant-a", "oidc", "source-a", "group-a", "dept-a", 10)
	store.addMapping("rule-b", "tenant-a", "oidc", "source-a", "group-b", "dept-b", 20)
	got, err := bindService(store, &fakeInvalidator{}).BindAndResolve(context.Background(), testIdentity("subject", "a@example.com", "group-a", "group-b"))
	if err != nil {
		t.Fatal(err)
	}
	if got.DepartmentID != "dept-a" || got.Mode != ModeAutomatic || !got.ChatAllowed {
		t.Fatalf("resolution=%+v", got)
	}
}

func TestEqualHighestPriorityMappingsToDifferentDepartmentsConflict(t *testing.T) {
	store := newFakeStore()
	store.addMapping("rule-a", "tenant-a", "oidc", "source-a", "group-a", "dept-a", 10)
	store.addMapping("rule-b", "tenant-a", "oidc", "source-a", "group-b", "dept-b", 10)
	got, err := bindService(store, &fakeInvalidator{}).BindAndResolve(context.Background(), testIdentity("subject", "a@example.com", "group-a", "group-b"))
	if err != nil {
		t.Fatal(err)
	}
	if got.DepartmentID != "dept-unassigned" || got.Mode != ModeConflict || !got.ChatAllowed {
		t.Fatalf("resolution=%+v", got)
	}
}

func TestNoMappingFallsBackToUnassignedAndAllowsChat(t *testing.T) {
	got, err := bindService(newFakeStore(), &fakeInvalidator{}).BindAndResolve(context.Background(), testIdentity("subject", "a@example.com"))
	if err != nil {
		t.Fatal(err)
	}
	if got.DepartmentID != "dept-unassigned" || got.Mode != ModeUnassigned || !got.ChatAllowed {
		t.Fatalf("resolution=%+v", got)
	}
}

func TestManualAssignmentIsNotOverwrittenUntilAutomaticIsExplicitlyRestored(t *testing.T) {
	store := newFakeStore()
	store.addMapping("rule-a", "tenant-a", "oidc", "source-a", "group-a", "dept-a", 10)
	service := bindService(store, &fakeInvalidator{})
	identity := testIdentity("subject", "a@example.com", "group-a")
	initial, err := service.BindAndResolve(context.Background(), identity)
	if err != nil {
		t.Fatal(err)
	}
	if err := service.AssignManually(context.Background(), "tenant-a", initial.UserID, "dept-b", "admin-1"); err != nil {
		t.Fatal(err)
	}
	manual, err := service.BindAndResolve(context.Background(), identity)
	if err != nil {
		t.Fatal(err)
	}
	if manual.DepartmentID != "dept-b" || manual.Mode != ModeManual || manual.Changed {
		t.Fatalf("manual assignment overwritten: %+v", manual)
	}
	if err := service.SetAutomatic(context.Background(), "tenant-a", initial.UserID, "admin-1"); err != nil {
		t.Fatal(err)
	}
	automatic, err := service.BindAndResolve(context.Background(), identity)
	if err != nil {
		t.Fatal(err)
	}
	if automatic.DepartmentID != "dept-a" || automatic.Mode != ModeAutomatic {
		t.Fatalf("automatic mapping not restored: %+v", automatic)
	}
}

func TestAssignManuallyAuditSourceIsAdmin(t *testing.T) {
	store := newFakeStore()
	store.users["tenant-a|user-a"] = User{
		ID: "user-a", TenantID: "tenant-a",
		DepartmentID: "dept-a", AssignmentMode: ModeAutomatic,
	}
	service := bindService(store, &fakeInvalidator{})
	if err := service.AssignManually(
		context.Background(), "tenant-a", "user-a", "dept-b", "admin-1",
	); err != nil {
		t.Fatal(err)
	}
	if len(store.audits) != 1 || store.audits[0].SourceID != "admin" {
		t.Fatalf("manual audit=%+v", store.audits)
	}
}

func TestSetAutomaticAuditSourceIsAdmin(t *testing.T) {
	store := newFakeStore()
	store.users["tenant-a|user-a"] = User{
		ID: "user-a", TenantID: "tenant-a",
		DepartmentID: "dept-b", AssignmentMode: ModeManual,
	}
	service := bindService(store, &fakeInvalidator{})
	if err := service.SetAutomatic(
		context.Background(), "tenant-a", "user-a", "admin-1",
	); err != nil {
		t.Fatal(err)
	}
	if len(store.audits) != 1 || store.audits[0].SourceID != "admin" {
		t.Fatalf("automatic audit=%+v", store.audits)
	}
}

func TestUnassignMovesUserToSystemDepartmentAndAudits(t *testing.T) {
	store := newFakeStore()
	store.users["tenant-a|user-a"] = User{
		ID: "user-a", TenantID: "tenant-a",
		DepartmentID: "dept-b", AssignmentMode: ModeManual,
	}
	service := bindService(store, &fakeInvalidator{})
	if err := service.Unassign(
		context.Background(), "tenant-a", "user-a", "admin-1",
	); err != nil {
		t.Fatal(err)
	}
	user := store.users["tenant-a|user-a"]
	if user.DepartmentID != "dept-unassigned" || user.AssignmentMode != ModeUnassigned ||
		user.AssignmentSource != assignmentSourceAdmin {
		t.Fatalf("unassigned user=%+v", user)
	}
	if len(store.audits) != 1 {
		t.Fatalf("audits=%+v", store.audits)
	}
	event := store.audits[0]
	if event.OldDepartmentID != "dept-b" || event.NewDepartmentID != "dept-unassigned" ||
		event.SourceID != assignmentSourceAdmin || event.ActorID != "admin-1" {
		t.Fatalf("unassign audit=%+v", event)
	}
}

func TestAssignManyManuallyRoleOnlyChangeAuditsAndInvalidates(t *testing.T) {
	store := newFakeStore()
	store.users["tenant-a|user-a"] = User{
		ID: "user-a", TenantID: "tenant-a", DepartmentID: "dept-a",
		AssignmentMode: ModeManual, AssignmentSource: assignmentSourceAdmin,
	}
	store.roles["tenant-a|user-a|dept-a"] = "member"

	err := bindService(store, &fakeInvalidator{}).AssignManyManually(
		context.Background(), "tenant-a", []string{"user-a"}, "dept-a", "owner", "admin-1",
	)
	if err != nil {
		t.Fatal(err)
	}
	if got := store.roles["tenant-a|user-a|dept-a"]; got != "owner" {
		t.Fatalf("department role=%q, want owner", got)
	}
	if len(store.audits) != 1 || len(store.events) != 1 {
		t.Fatalf("role-only change audit=%d cache events=%d", len(store.audits), len(store.events))
	}
	event := store.audits[0]
	if event.OldDepartmentID != "dept-a" || event.NewDepartmentID != "dept-a" ||
		event.OldRole != "member" || event.NewRole != "owner" {
		t.Fatalf("role-only event=%+v", event)
	}
}

func TestAssignManyManuallyLocksUsersInStableOrder(t *testing.T) {
	store := newFakeStore()
	for _, userID := range []string{"user-a", "user-b"} {
		store.users["tenant-a|"+userID] = User{
			ID: userID, TenantID: "tenant-a", DepartmentID: "dept-a",
			AssignmentMode: ModeManual, AssignmentSource: assignmentSourceAdmin,
		}
		store.roles["tenant-a|"+userID+"|dept-a"] = "member"
	}

	err := bindService(store, &fakeInvalidator{}).AssignManyManually(
		context.Background(), "tenant-a", []string{"user-b", "user-a"},
		"dept-a", "member", "admin-1",
	)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(store.getUserCalls, ","); got != "user-a,user-b" {
		t.Fatalf("GetUser order=%q, want stable user-a,user-b", got)
	}
}

func TestEmergencyUserIsDeniedChatAndMayHaveNoDepartment(t *testing.T) {
	store := newFakeStore()
	identity := testIdentity("emergency-subject", "emergency@example.com")
	user := User{ID: "emergency-user", TenantID: "tenant-a", Role: "platform_admin", Status: "active", AssignmentMode: ModeEmergency}
	store.users["tenant-a|emergency-user"] = user
	store.links[stableKey(identity)] = UserIdentityLink{
		ID: "link-emergency", TenantID: "tenant-a", UserID: user.ID, Issuer: identity.Issuer,
		SourceID: identity.SourceID, SourceType: identity.SourceType, ExternalSubject: identity.ExternalSubject,
	}
	got, err := bindService(store, &fakeInvalidator{}).BindAndResolve(context.Background(), identity)
	if err != nil {
		t.Fatal(err)
	}
	if !got.PortalAllowed || got.ChatAllowed || got.DepartmentID != "" || got.Mode != ModeEmergency {
		t.Fatalf("resolution=%+v", got)
	}
	if err := bindService(store, &fakeInvalidator{}).AssignManually(
		context.Background(), "tenant-a", user.ID, "dept-a", "admin-1",
	); !errors.Is(err, ErrConflict) {
		t.Fatalf("emergency assignment error=%v", err)
	}
}

func TestTransitionPlatformRoleToEmergencyClearsDepartmentAndQueuesInvalidation(t *testing.T) {
	store := newFakeStore()
	store.users["tenant-a|user-a"] = User{
		ID: "user-a", TenantID: "tenant-a", Role: "viewer", DepartmentID: "dept-a",
		AssignmentMode: ModeManual, AssignmentSource: assignmentSourceAdmin,
	}
	store.grants["tenant-a|user-a"] = "viewer"
	err := NewService(store).TransitionPlatformRole(
		context.Background(), "tenant-a", "user-a", "platform_admin", "", "admin-1",
	)
	if err != nil {
		t.Fatal(err)
	}
	got := store.users["tenant-a|user-a"]
	if got.Role != "platform_admin" || got.DepartmentID != "" ||
		got.AssignmentMode != ModeEmergency || got.AssignmentSource != assignmentSourceAdmin {
		t.Fatalf("user=%+v", got)
	}
	if grant := store.grants["tenant-a|user-a"]; grant != "platform_admin" {
		t.Fatalf("tenant grant=%q want platform_admin", grant)
	}
	if len(store.audits) != 1 || len(store.events) != 1 {
		t.Fatalf("audit=%d outbox=%d", len(store.audits), len(store.events))
	}
	event := store.audits[0]
	if event.OldDepartmentID != "dept-a" || event.NewDepartmentID != "" ||
		event.OldRole != "viewer" || event.NewRole != "platform_admin" {
		t.Fatalf("event=%+v", event)
	}
}

func TestTransitionPlatformRoleFromEmergencyAssignsDepartmentAndQueuesInvalidation(t *testing.T) {
	store := newFakeStore()
	store.users["tenant-a|user-a"] = User{
		ID: "user-a", TenantID: "tenant-a", Role: "platform_admin",
		AssignmentMode: ModeEmergency, AssignmentSource: "local",
	}
	store.grants["tenant-a|user-a"] = "platform_admin"
	err := NewService(store).TransitionPlatformRole(
		context.Background(), "tenant-a", "user-a", "viewer", "dept-a", "admin-1",
	)
	if err != nil {
		t.Fatal(err)
	}
	got := store.users["tenant-a|user-a"]
	if got.Role != "viewer" || got.DepartmentID != "dept-a" ||
		got.AssignmentMode != ModeManual || got.AssignmentSource != assignmentSourceAdmin {
		t.Fatalf("user=%+v", got)
	}
	if grant := store.grants["tenant-a|user-a"]; grant != "viewer" {
		t.Fatalf("tenant grant=%q want viewer", grant)
	}
	if len(store.audits) != 1 || len(store.events) != 1 {
		t.Fatalf("audit=%d outbox=%d", len(store.audits), len(store.events))
	}
}

func TestTransitionPlatformRoleRejectsCrossTenantDepartmentWithoutSideEffects(t *testing.T) {
	store := newFakeStore()
	want := User{
		ID: "user-a", TenantID: "tenant-a", Role: "platform_admin",
		AssignmentMode: ModeEmergency, AssignmentSource: "local",
	}
	store.users["tenant-a|user-a"] = want
	err := NewService(store).TransitionPlatformRole(
		context.Background(), "tenant-a", "user-a", "viewer", "dept-b-other", "admin-1",
	)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("error=%v", err)
	}
	got := store.users["tenant-a|user-a"]
	if got != want || len(store.audits) != 0 || len(store.events) != 0 {
		t.Fatalf("user=%+v audits=%v outbox=%v", got, store.audits, store.events)
	}
}

func TestDepartmentChangeQueuesDedicatedCacheInvalidation(t *testing.T) {
	store := newFakeStore()
	store.addMapping("rule-a", "tenant-a", "oidc", "source-a", "group-a", "dept-a", 10)
	invalidator := &fakeInvalidator{}
	service := bindService(store, invalidator)
	identity := testIdentity("subject", "a@example.com", "group-a")
	_, err := service.BindAndResolve(context.Background(), identity)
	if err != nil {
		t.Fatal(err)
	}
	store.mappings = nil
	store.addMapping("rule-b", "tenant-a", "oidc", "source-a", "group-a", "dept-b", 10)
	changed, err := service.BindAndResolve(context.Background(), identity)
	if err != nil {
		t.Fatal(err)
	}
	if !changed.Changed || changed.DepartmentID != "dept-b" {
		t.Fatalf("resolution=%+v", changed)
	}
	stored := store.users["tenant-a|"+changed.UserID]
	if changed.DepartmentVersion == 0 || changed.DepartmentVersion != stored.DepartmentVersion {
		t.Fatalf("resolution version=%v stored version=%v", changed.DepartmentVersion, stored.DepartmentVersion)
	}
	if len(store.events) != 2 {
		t.Fatalf("dedicated invalidation event count=%d", len(store.events))
	}
	if len(invalidator.calls) != 0 || len(invalidator.modelCalls) != 0 {
		t.Fatalf("binding transaction must not synchronously invalidate caches: permission=%v model=%v",
			invalidator.calls, invalidator.modelCalls)
	}
}

func TestBindingCommitDoesNotDependOnSynchronousInvalidator(t *testing.T) {
	store := newFakeStore()
	store.addMapping("rule-a", "tenant-a", "oidc", "source-a", "group-a", "dept-a", 10)
	invalidator := &fakeInvalidator{modelErr: errors.New("model cache unavailable")}
	got, err := bindService(store, invalidator).BindAndResolve(context.Background(), testIdentity("subject", "a@example.com", "group-a"))
	if err != nil {
		t.Fatalf("err=%v", err)
	}
	if got.DepartmentID != "dept-a" || !got.Changed {
		t.Fatalf("committed resolution lost: %+v", got)
	}
	if len(store.events) != 1 {
		t.Fatalf("retryable event count=%d", len(store.events))
	}
	for _, processed := range store.events {
		if processed {
			t.Fatal("failed invalidation event must remain pending")
		}
	}
	if len(invalidator.calls) != 0 || len(invalidator.modelCalls) != 0 {
		t.Fatal("reconciler, not binding service, must own cache invalidation")
	}
}

func TestCrossTenantObjectsAreNotVisible(t *testing.T) {
	store := newFakeStore()
	store.users["tenant-b|user-b"] = User{ID: "user-b", TenantID: "tenant-b", DepartmentID: "dept-b-other", AssignmentMode: ModeManual}
	service := bindService(store, &fakeInvalidator{})
	if err := service.AssignManually(context.Background(), "tenant-a", "user-b", "dept-a", "admin-a"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant user error=%v", err)
	}
	if err := service.AssignManually(context.Background(), "tenant-a", "missing", "dept-b-other", "admin-a"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("cross-tenant department error=%v", err)
	}
}

func TestManualAssignmentTargetVisibilityErrorsAreIndistinguishable(t *testing.T) {
	tests := []struct {
		name         string
		many         bool
		departmentID string
	}{
		{name: "single missing department", departmentID: "missing"},
		{name: "single cross-tenant department", departmentID: "dept-b-other"},
		{name: "single system unassigned department", departmentID: "dept-unassigned"},
		{name: "batch missing department", many: true, departmentID: "missing"},
		{name: "batch cross-tenant department", many: true, departmentID: "dept-b-other"},
		{name: "batch system unassigned department", many: true, departmentID: "dept-unassigned"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			store := newFakeStore()
			store.users["tenant-a|user-a"] = User{
				ID: "user-a", TenantID: "tenant-a", DepartmentID: "dept-a", AssignmentMode: ModeManual,
			}
			service := bindService(store, &fakeInvalidator{})
			var err error
			if test.many {
				err = service.AssignManyManually(
					context.Background(), "tenant-a", []string{"user-a"}, test.departmentID, "member", "admin-a",
				)
			} else {
				err = service.AssignManually(
					context.Background(), "tenant-a", "user-a", test.departmentID, "admin-a",
				)
			}
			if err != ErrNotFound {
				t.Fatalf("error=%v, want exact ErrNotFound", err)
			}
			if got := store.users["tenant-a|user-a"]; got.DepartmentID != "dept-a" {
				t.Fatalf("user mutated after hidden target: %+v", got)
			}
			if len(store.audits) != 0 || len(store.roles) != 0 {
				t.Fatalf("side effects after hidden target: audits=%d roles=%d", len(store.audits), len(store.roles))
			}
		})
	}
}

func TestConcurrentStableKeyHasOneWinner(t *testing.T) {
	store := newFakeStore()
	store.addMapping("rule-a", "tenant-a", "oidc", "source-a", "group-a", "dept-a", 10)
	service := bindService(store, &fakeInvalidator{})
	identity := testIdentity("concurrent-subject", "same@example.com", "group-a")
	const workers = 16
	start := make(chan struct{})
	results := make(chan Resolution, workers)
	errs := make(chan error, workers)
	var wait sync.WaitGroup
	for index := 0; index < workers; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			resolution, err := service.BindAndResolve(context.Background(), identity)
			results <- resolution
			errs <- err
		}()
	}
	close(start)
	wait.Wait()
	close(results)
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	winner := ""
	for result := range results {
		if winner == "" {
			winner = result.UserID
		}
		if result.UserID != winner {
			t.Fatalf("multiple winners: %s and %s", winner, result.UserID)
		}
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if len(store.links) != 1 || len(store.users) != 1 {
		t.Fatalf("links=%d users=%d", len(store.links), len(store.users))
	}
}

func TestDirectoryIdentityRequiresSourceIDEqualIssuer(t *testing.T) {
	service := bindService(newFakeStore(), &fakeInvalidator{})
	identity := testIdentity("subject", "a@example.com")
	identity.SourceType = "ldap"
	identity.Issuer = "directory-source-1"
	identity.SourceID = "directory-source-2"
	if _, err := service.BindAndResolve(context.Background(), identity); !errors.Is(err, ErrInvalidIdentity) {
		t.Fatalf("err=%v", err)
	}
}

func TestBindAndResolveRejectsOversizedIdentityClaims(t *testing.T) {
	base := testIdentity("subject", "a@example.com", "group-a")
	tests := []struct {
		name   string
		mutate func(*ExternalIdentity)
	}{
		{"tenant", func(identity *ExternalIdentity) { identity.TenantID = strings.Repeat("t", 65) }},
		{"issuer", func(identity *ExternalIdentity) { identity.Issuer = strings.Repeat("i", 513) }},
		{"source id", func(identity *ExternalIdentity) { identity.SourceID = strings.Repeat("s", 65) }},
		{"subject", func(identity *ExternalIdentity) { identity.ExternalSubject = strings.Repeat("s", 513) }},
		{"username", func(identity *ExternalIdentity) { identity.Username = strings.Repeat("u", 256) }},
		{"email", func(identity *ExternalIdentity) { identity.Email = strings.Repeat("e", 256) }},
		{"group", func(identity *ExternalIdentity) { identity.Groups = []string{strings.Repeat("g", 2049)} }},
		{"group count", func(identity *ExternalIdentity) { identity.Groups = make([]string, 513) }},
		{"invalid utf8", func(identity *ExternalIdentity) { identity.Username = string([]byte{0xff}) }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			identity := base
			test.mutate(&identity)
			_, err := bindService(newFakeStore(), &fakeInvalidator{}).BindAndResolve(context.Background(), identity)
			if !errors.Is(err, ErrInvalidIdentity) {
				t.Fatalf("err=%v", err)
			}
		})
	}
}

func TestAuditEventContainsOnlyBoundedIdentityMetadata(t *testing.T) {
	store := newFakeStore()
	store.addMapping("rule-a", "tenant-a", "oidc", "source-a", "group-a", "dept-a", 10)
	_, err := bindService(store, &fakeInvalidator{}).BindAndResolve(context.Background(), testIdentity("subject", "secret@example.com", "group-a"))
	if err != nil {
		t.Fatal(err)
	}
	if len(store.audits) != 1 {
		t.Fatalf("audits=%d", len(store.audits))
	}
	event := fmt.Sprintf("%+v", store.audits[0])
	for _, secret := range []string{"secret@example.com", "subject", "group-a"} {
		if contains(event, secret) {
			t.Fatalf("audit leaked directory identity material: %s", event)
		}
	}
}

func contains(value, needle string) bool {
	for index := 0; index+len(needle) <= len(value); index++ {
		if value[index:index+len(needle)] == needle {
			return true
		}
	}
	return false
}

func TestNewOidcAndDirectoryUsersDefaultToChatOnly(t *testing.T) {
	for _, sourceType := range []string{"oidc", "ldap", "ad"} {
		t.Run(sourceType, func(t *testing.T) {
			store := newFakeStore()
			identity := testIdentity("new-"+sourceType, "employee@example.com")
			identity.SourceType = sourceType
			if sourceType != "oidc" {
				identity.Issuer = identity.SourceID
			}
			resolution, err := bindService(store, &fakeInvalidator{}).BindAndResolve(context.Background(), identity)
			if err != nil {
				t.Fatal(err)
			}
			if got := store.users["tenant-a|"+resolution.UserID].Role; got != "chat_user" {
				t.Fatalf("new role=%q, want chat_user", got)
			}
		})
	}
}
