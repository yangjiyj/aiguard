package permission

import (
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
)

// RoutePermission describes the permission required for a route pattern
type RoutePermission struct {
	Resource      string
	Action        string
	ScopeType     string // tenant | team | project | none
	ScopeIDSource string // "url:{param}" | "tenant" | "body:field" | ""
}

// routeTable maps "METHOD /admin/v1/path/template" to RoutePermission
// Path params use {id} style placeholders
var routeTable = map[string]RoutePermission{
	"GET /admin/v1/integration/credential-hits":                {Resource: "integration_events", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/integration/retention-status":               {Resource: "integration_events", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/integration/agent-credentials/{id}":         {Resource: "agent_credentials", Action: "read", ScopeType: "tenant"},
	"PATCH /admin/v1/integration/agent-credentials/{id}":       {Resource: "agent_credentials", Action: "write", ScopeType: "tenant"},
	"GET /admin/v1/integration/dlp-status":                     {Resource: "security_policies", Action: "read", ScopeType: "tenant"},
	"POST /admin/v1/employee-login":                            {Resource: "identity_sources", Action: "read", ScopeType: "none"},
	"GET /admin/v1/integration/projects":                       {Resource: "integration_projects", Action: "read", ScopeType: "tenant"},
	"POST /admin/v1/integration/agent-credentials":             {Resource: "agent_credentials", Action: "write", ScopeType: "tenant"},
	"GET /admin/v1/integration/agent-credentials":              {Resource: "agent_credentials", Action: "read", ScopeType: "tenant"},
	"POST /admin/v1/integration/agent-credentials/{id}/rotate": {Resource: "agent_credentials", Action: "write", ScopeType: "tenant"},
	"POST /admin/v1/integration/agent-credentials/{id}/revoke": {Resource: "agent_credentials", Action: "write", ScopeType: "tenant"},
	"POST /admin/v1/integration/agent-policies":                {Resource: "agent_enforcement_policies", Action: "write", ScopeType: "tenant"},
	"PUT /admin/v1/integration/agent-policies/{id}":            {Resource: "agent_enforcement_policies", Action: "write", ScopeType: "tenant"},
	"GET /admin/v1/integration/agent-policies":                 {Resource: "agent_enforcement_policies", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/integration/enforcement-status":             {Resource: "gateway_enforcement_status", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/integration/audit-events":                   {Resource: "integration_events", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/integration/upstreams":                      {Resource: "integration_upstreams", Action: "read", ScopeType: "tenant"},
	"POST /admin/v1/internal/agent/identity-events":            {Resource: "agent_sessions", Action: "write", ScopeType: "tenant"},
	"GET /admin/v1/agent/native-events":                        {Resource: "agent_sessions", Action: "read", ScopeType: "tenant"},
	"POST /admin/v1/internal/agent/endpoints/resolve":          {Resource: "agent_endpoints", Action: "read", ScopeType: "tenant"},
	"POST /admin/v1/internal/agent/endpoints/register":         {Resource: "agent_enrollment", Action: "admin", ScopeType: "tenant"},
	"POST /admin/v1/internal/agent/endpoints/heartbeat":        {Resource: "agent_endpoints", Action: "write", ScopeType: "tenant"},
	"POST /admin/v1/internal/agent/events":                     {Resource: "agent_sessions", Action: "write", ScopeType: "tenant"},
	"POST /admin/v1/internal/agent/probe-reports":              {Resource: "agent_endpoints", Action: "write", ScopeType: "tenant"},
	"GET /admin/v1/internal/agent/policy-bundle":               {Resource: "agent_endpoints", Action: "read", ScopeType: "tenant"},

	"GET /admin/v1/agent/overview":                                        {Resource: "agent_endpoints", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/agent/endpoints":                                       {Resource: "agent_endpoints", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/agent/endpoints/{id}":                                  {Resource: "agent_endpoints", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/agent/kubernetes/clusters":                             {Resource: "agent_endpoints", Action: "read", ScopeType: "tenant"},
	"POST /admin/v1/agent/kubernetes/clusters":                            {Resource: "agent_endpoints", Action: "write", ScopeType: "tenant"},
	"POST /admin/v1/agent/kubernetes/clusters/{cluster_id}/namespaces":    {Resource: "agent_endpoints", Action: "write", ScopeType: "tenant"},
	"POST /admin/v1/agent/kubernetes/namespaces/{registration_id}/revoke": {Resource: "agent_endpoints", Action: "write", ScopeType: "tenant"},
	"GET /admin/v1/agent/kubernetes/clusters/{cluster_id}/coverage":       {Resource: "agent_endpoints", Action: "read", ScopeType: "tenant"},
	"PUT /admin/v1/agent/endpoints/{id}/mode":                             {Resource: "agent_endpoints", Action: "write", ScopeType: "tenant"},
	"POST /admin/v1/agent/endpoints/{id}/revoke":                          {Resource: "agent_endpoints", Action: "write", ScopeType: "tenant"},
	"POST /admin/v1/agent/endpoints/{id}/rotate-token":                    {Resource: "agent_endpoints", Action: "write", ScopeType: "tenant"},
	"GET /admin/v1/agent/enrollment-tokens":                               {Resource: "agent_enrollment", Action: "admin", ScopeType: "tenant"},
	"POST /admin/v1/agent/enrollment-tokens":                              {Resource: "agent_enrollment", Action: "admin", ScopeType: "tenant"},
	"POST /admin/v1/agent/enrollment-tokens/{id}/revoke":                  {Resource: "agent_enrollment", Action: "admin", ScopeType: "tenant"},
	"GET /admin/v1/agent/sessions":                                        {Resource: "agent_sessions", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/agent/sessions/{id}":                                   {Resource: "agent_sessions", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/agent/events":                                          {Resource: "agent_sessions", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/agent/assets":                                          {Resource: "agent_endpoints", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/agent/unified-assets":                                  {Resource: "agent_endpoints", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/agent/unified-assets/native-reference-link":            {Resource: "agent_endpoints", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/agent/unified-assets/{id}/history":                     {Resource: "agent_endpoints", Action: "read", ScopeType: "tenant"},
	"PUT /admin/v1/agent/unified-assets/{id}/ownership":                   {Resource: "agent_endpoints", Action: "write", ScopeType: "tenant"},
	"PUT /admin/v1/agent/unified-assets/{id}/catalog":                     {Resource: "agent_endpoints", Action: "write", ScopeType: "tenant"},
	"PUT /admin/v1/agent/unified-assets/{id}/sources":                     {Resource: "agent_endpoints", Action: "write", ScopeType: "tenant"},
	"POST /admin/v1/agent/unified-assets/{id}/merge":                      {Resource: "agent_endpoints", Action: "write", ScopeType: "tenant"},
	"GET /admin/v1/agent/approval-rules":                                  {Resource: "agent_endpoints", Action: "read", ScopeType: "tenant"},
	"POST /admin/v1/agent/approval-rules":                                 {Resource: "agent_endpoints", Action: "write", ScopeType: "tenant"},
	"POST /admin/v1/agent/approval-rules/{id}/deactivate":                 {Resource: "agent_endpoints", Action: "write", ScopeType: "tenant"},
	"GET /admin/v1/agent/policy-bundles":                                  {Resource: "agent_endpoints", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/agent/policy-bundles/current":                          {Resource: "agent_endpoints", Action: "read", ScopeType: "tenant"},

	"GET /admin/v1/agent/principals":                      {Resource: "agent_principals", Action: "read", ScopeType: "tenant"},
	"POST /admin/v1/agent/principals":                     {Resource: "agent_principals", Action: "admin", ScopeType: "tenant"},
	"POST /admin/v1/agent/principals/{id}/revoke":         {Resource: "agent_principals", Action: "admin", ScopeType: "tenant"},
	"POST /admin/v1/agent/principals/{id}/rotate-token":   {Resource: "agent_principals", Action: "admin", ScopeType: "tenant"},
	"POST /admin/v1/agent/authorize":                      {Resource: "agent_authorization", Action: "check", ScopeType: "none"},
	"POST /admin/v1/agent/approval-requests":              {Resource: "agent_authorization", Action: "check", ScopeType: "none"},
	"POST /admin/v1/agent/approval-claims":                {Resource: "agent_authorization", Action: "check", ScopeType: "none"},
	"GET /admin/v1/agent/intent-tasks/{id}":               {Resource: "agent_intent_tasks", Action: "read", ScopeType: "tenant"},
	"POST /admin/v1/agent/intent-tasks":                   {Resource: "agent_intent_tasks", Action: "admin", ScopeType: "tenant"},
	"POST /admin/v1/agent/intent-tasks/{id}/revoke":       {Resource: "agent_intent_tasks", Action: "admin", ScopeType: "tenant"},
	"GET /admin/v1/agent/principals/{id}/delegation-tree": {Resource: "agent_principals", Action: "read", ScopeType: "tenant"},
	"POST /admin/v1/agent/delegations":                    {Resource: "agent_authorization", Action: "check", ScopeType: "none"},
	"POST /admin/v1/agent/delegations/{id}/revoke":        {Resource: "agent_authorization", Action: "check", ScopeType: "none"},
	"GET /admin/v1/agent/delegations/{id}/calls":          {Resource: "agent_authorization", Action: "check", ScopeType: "none"},

	// Users
	"GET /admin/v1/users":                      {Resource: "users", Action: "read", ScopeType: "tenant"},
	"POST /admin/v1/users":                     {Resource: "users", Action: "write", ScopeType: "tenant"},
	"PATCH /admin/v1/users/{id}":               {Resource: "users", Action: "write", ScopeType: "tenant"},
	"DELETE /admin/v1/users/{id}":              {Resource: "users", Action: "delete", ScopeType: "tenant"},
	"POST /admin/v1/users/{id}/reset-password": {Resource: "users", Action: "write", ScopeType: "tenant"},
	// W3 控制台登录安全
	"POST /admin/v1/users/{id}/unlock-login":                                {Resource: "users", Action: "write", ScopeType: "tenant"},
	"POST /admin/v1/users/{id}/reset-totp":                                  {Resource: "users", Action: "write", ScopeType: "tenant"},
	"GET /admin/v1/system/login-security":                                   {Resource: "system_config", Action: "read", ScopeType: "tenant"},
	"PUT /admin/v1/system/login-security":                                   {Resource: "users", Action: "write", ScopeType: "tenant"},
	"GET /admin/v1/system/portal-login-baseline":                            {Resource: "system_config", Action: "read", ScopeType: "tenant"},
	"POST /admin/v1/users/{id}/department/automatic":                        {Resource: "users", Action: "write", ScopeType: "tenant"},
	"PATCH /admin/v1/users/{id}/status":                                     {Resource: "users", Action: "write", ScopeType: "tenant"},
	"GET /admin/v1/users/{id}/grants":                                       {Resource: "users.grants", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/users/{id}/keys":                                         {Resource: "api_keys", Action: "read", ScopeType: "tenant"},
	"POST /admin/v1/users/{id}/grants":                                      {Resource: "users.grants", Action: "write", ScopeType: "tenant"},
	"DELETE /admin/v1/users/{id}/grants/{grant_id}":                         {Resource: "users.grants", Action: "delete", ScopeType: "tenant"},
	"GET /admin/v1/users/{id}/login-history":                                {Resource: "users", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/audit/login-history":                                     {Resource: "audit_chain", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/users/{id}/detail":                                       {Resource: "users", Action: "read", ScopeType: "tenant"},
	"POST /admin/v1/users/{id}/merge/preview":                               {Resource: "users", Action: "read", ScopeType: "tenant"},
	"POST /admin/v1/users/{id}/merge":                                       {Resource: "users", Action: "write", ScopeType: "tenant"},
	"POST /admin/v1/users/{id}/identity-links/{link_id}/rebind":             {Resource: "users", Action: "write", ScopeType: "tenant"},
	"GET /admin/v1/users/{id}/model-access":                                 {Resource: "users", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/users/{id}/model-access/extra-grants":                    {Resource: "users", Action: "read", ScopeType: "tenant"},
	"POST /admin/v1/users/{id}/model-access/extra-grants":                   {Resource: "users", Action: "write", ScopeType: "tenant"},
	"POST /admin/v1/users/{id}/model-access/extra-grants/{grant_id}/revoke": {Resource: "users", Action: "write", ScopeType: "tenant"},
	"PUT /admin/v1/users/{id}/model-access":                                 {Resource: "users", Action: "write", ScopeType: "tenant"},
	"GET /admin/v1/users/{id}/usage/summary":                                {Resource: "saving_metrics", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/users/{id}/usage/trend":                                  {Resource: "saving_metrics", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/users/{id}/usage/by-model":                               {Resource: "saving_metrics", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/users/{id}/usage/records":                                {Resource: "saving_metrics", Action: "read", ScopeType: "tenant"},

	// Teams
	"GET /admin/v1/teams":                          {Resource: "teams", Action: "read", ScopeType: "tenant"},
	"POST /admin/v1/teams":                         {Resource: "teams", Action: "write", ScopeType: "tenant"},
	"PATCH /admin/v1/teams/{id}":                   {Resource: "teams", Action: "write", ScopeType: "tenant"},
	"DELETE /admin/v1/teams/{id}":                  {Resource: "teams", Action: "delete", ScopeType: "team", ScopeIDSource: "url:id"},
	"GET /admin/v1/teams/{id}/members":             {Resource: "teams.members", Action: "read", ScopeType: "team", ScopeIDSource: "url:id"},
	"POST /admin/v1/teams/{id}/members":            {Resource: "teams.members", Action: "write", ScopeType: "team", ScopeIDSource: "url:id"},
	"DELETE /admin/v1/teams/{id}/members/{userId}": {Resource: "teams.members", Action: "delete", ScopeType: "team", ScopeIDSource: "url:id"},

	// Tenants
	"GET /admin/v1/tenants":        {Resource: "users", Action: "read", ScopeType: "tenant"},
	"POST /admin/v1/tenants":       {Resource: "users", Action: "write", ScopeType: "tenant"},
	"GET /admin/v1/tenants/{id}":   {Resource: "tenants", Action: "read", ScopeType: "tenant"},
	"PATCH /admin/v1/tenants/{id}": {Resource: "users", Action: "write", ScopeType: "tenant"},

	// Projects
	"GET /admin/v1/projects":                        {Resource: "projects", Action: "read", ScopeType: "tenant"},
	"POST /admin/v1/projects":                       {Resource: "projects", Action: "write", ScopeType: "tenant"},
	"GET /admin/v1/projects/{id}":                   {Resource: "projects", Action: "read", ScopeType: "tenant"},
	"PATCH /admin/v1/projects/{id}":                 {Resource: "projects", Action: "write", ScopeType: "tenant"},
	"DELETE /admin/v1/projects/{id}":                {Resource: "projects", Action: "delete", ScopeType: "tenant"},
	"GET /admin/v1/projects/{id}/users":             {Resource: "project_users", Action: "read", ScopeType: "project", ScopeIDSource: "url:id"},
	"POST /admin/v1/projects/{id}/users":            {Resource: "project_users", Action: "write", ScopeType: "project", ScopeIDSource: "url:id"},
	"DELETE /admin/v1/projects/{id}/users/{userId}": {Resource: "project_users", Action: "delete", ScopeType: "project", ScopeIDSource: "url:id"},
	"PATCH /admin/v1/projects/{id}/model-config":    {Resource: "projects", Action: "write", ScopeType: "project", ScopeIDSource: "url:id"},

	// Keys
	"GET /admin/v1/keys":                    {Resource: "api_keys", Action: "read", ScopeType: "tenant"},
	"POST /admin/v1/keys":                   {Resource: "api_keys", Action: "write", ScopeType: "tenant"},
	"PATCH /admin/v1/keys/{id}":             {Resource: "api_keys", Action: "write", ScopeType: "tenant"},
	"PUT /admin/v1/keys/{id}/traffic-class": {Resource: "api_keys", Action: "write", ScopeType: "tenant"},
	"POST /admin/v1/keys/{id}/revoke":       {Resource: "api_keys", Action: "write", ScopeType: "tenant"},
	"GET /admin/v1/keys/{id}/reveal":        {Resource: "api_keys", Action: "read", ScopeType: "tenant"},
	"DELETE /admin/v1/keys/{id}":            {Resource: "api_keys", Action: "delete", ScopeType: "tenant"},

	// Providers
	"GET /admin/v1/providers":                          {Resource: "providers", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/providers/metrics":                  {Resource: "providers", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/providers/deleted":                  {Resource: "providers", Action: "read", ScopeType: "tenant"},
	"POST /admin/v1/providers":                         {Resource: "providers", Action: "write", ScopeType: "tenant"},
	"PATCH /admin/v1/providers/{id}":                   {Resource: "providers", Action: "write", ScopeType: "tenant"},
	"GET /admin/v1/providers/{id}/credentials/history": {Resource: "providers", Action: "read", ScopeType: "tenant"},
	"POST /admin/v1/providers/{id}/restore":            {Resource: "providers", Action: "write", ScopeType: "tenant"},
	"DELETE /admin/v1/providers/{id}":                  {Resource: "providers", Action: "delete", ScopeType: "tenant"},

	// Models
	"GET /admin/v1/model-operations/overview":          {Resource: "models", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/model-operations/sla":               {Resource: "models", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/model-operations/sla/export":        {Resource: "models", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/model-operations/targets":           {Resource: "models", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/model-operations/history":           {Resource: "models", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/model-operations/quality":           {Resource: "models", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/model-operations/providers":         {Resource: "models", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/model-operations/alerts":            {Resource: "models", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/model-operations/config":            {Resource: "models", Action: "read", ScopeType: "tenant"},
	"PUT /admin/v1/model-operations/config":            {Resource: "models", Action: "write", ScopeType: "tenant"},
	"POST /admin/v1/model-operations/test":             {Resource: "models", Action: "write", ScopeType: "tenant"},
	"GET /admin/v1/model-operations/jobs/{id}":         {Resource: "models", Action: "read", ScopeType: "tenant"},
	"POST /admin/v1/model-operations/jobs/{id}/cancel": {Resource: "models", Action: "write", ScopeType: "tenant"},
	"POST /admin/v1/model-operations/alerts/{id}/ack":  {Resource: "models", Action: "write", ScopeType: "tenant"},
	"GET /admin/v1/models":                             {Resource: "models", Action: "read", ScopeType: "tenant"},
	"POST /admin/v1/models":                            {Resource: "models", Action: "write", ScopeType: "tenant"},
	"GET /admin/v1/models/eval-status":                 {Resource: "models", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/models/sync/state":                  {Resource: "models", Action: "read", ScopeType: "tenant"},
	"PUT /admin/v1/models/sync/state":                  {Resource: "models", Action: "write", ScopeType: "tenant"},
	"POST /admin/v1/models/sync":                       {Resource: "models", Action: "write", ScopeType: "tenant"},
	"POST /admin/v1/models/sync/candidates":            {Resource: "models", Action: "write", ScopeType: "tenant"},
	"POST /admin/v1/models/batch-delete":               {Resource: "models", Action: "delete", ScopeType: "tenant"},
	"POST /admin/v1/models/sync/preview":               {Resource: "models", Action: "write", ScopeType: "tenant"},
	"POST /admin/v1/models/sync/verify":                {Resource: "models", Action: "write", ScopeType: "tenant"},
	"POST /admin/v1/models/sync/commit":                {Resource: "models", Action: "write", ScopeType: "tenant"},
	"DELETE /admin/v1/models/{id}":                     {Resource: "models", Action: "delete", ScopeType: "tenant"},
	"PATCH /admin/v1/models/{id}/routing":              {Resource: "routing_policies", Action: "write", ScopeType: "tenant"},
	"PATCH /admin/v1/models/{id}/status":               {Resource: "models", Action: "write", ScopeType: "tenant"},
	"PATCH /admin/v1/models/{id}/proxy-config":         {Resource: "models", Action: "write", ScopeType: "tenant"},
	"PATCH /admin/v1/models/{id}/capabilities":         {Resource: "models", Action: "write", ScopeType: "tenant"},

	// Policies
	"GET /admin/v1/policies/model": {Resource: "models", Action: "read", ScopeType: "tenant"},
	"PUT /admin/v1/policies/model": {Resource: "models", Action: "write", ScopeType: "tenant"},

	"GET /admin/v1/group-mapping-rules":         {Resource: "group_mapping_rules", Action: "read", ScopeType: "tenant"},
	"POST /admin/v1/group-mapping-rules":        {Resource: "group_mapping_rules", Action: "write", ScopeType: "tenant"},
	"PATCH /admin/v1/group-mapping-rules/{id}":  {Resource: "group_mapping_rules", Action: "write", ScopeType: "tenant"},
	"DELETE /admin/v1/group-mapping-rules/{id}": {Resource: "group_mapping_rules", Action: "delete", ScopeType: "tenant"},
	"GET /admin/v1/policies/quota":              {Resource: "quota_policies", Action: "read", ScopeType: "tenant"},
	"PUT /admin/v1/policies/quota":              {Resource: "quota_policies", Action: "write", ScopeType: "tenant"},

	// Identity sources
	"GET /admin/v1/identity/sources":                {Resource: "identity_sources", Action: "read", ScopeType: "tenant"},
	"PUT /admin/v1/identity/sources/draft":          {Resource: "identity_sources", Action: "write", ScopeType: "tenant"},
	"POST /admin/v1/identity/sources/test":          {Resource: "identity_sources", Action: "write", ScopeType: "tenant"},
	"POST /admin/v1/identity/sources/activate":      {Resource: "identity_sources", Action: "write", ScopeType: "tenant"},
	"POST /admin/v1/identity/sources/disable":       {Resource: "identity_sources", Action: "write", ScopeType: "tenant"},
	"POST /admin/v1/identity/sources/reconcile":     {Resource: "identity_sources", Action: "manage", ScopeType: "tenant"},
	"POST /admin/v1/identity/sources/adopt-runtime": {Resource: "identity_sources", Action: "manage", ScopeType: "tenant"},
	"GET /admin/v1/identity/dept-mappings":          {Resource: "identity_sources", Action: "read", ScopeType: "tenant"},
	"POST /admin/v1/identity/dept-mappings":         {Resource: "identity_sources", Action: "write", ScopeType: "tenant"},
	"PATCH /admin/v1/identity/dept-mappings/{id}":   {Resource: "identity_sources", Action: "write", ScopeType: "tenant"},
	"DELETE /admin/v1/identity/dept-mappings/{id}":  {Resource: "identity_sources", Action: "delete", ScopeType: "tenant"},
	// Unified department mappings (identity_department_mappings)
	"GET /admin/v1/identity/department-mappings":          {Resource: "identity_sources", Action: "read", ScopeType: "tenant"},
	"POST /admin/v1/identity/department-mappings":         {Resource: "identity_sources", Action: "manage", ScopeType: "tenant"},
	"PATCH /admin/v1/identity/department-mappings/{id}":   {Resource: "identity_sources", Action: "manage", ScopeType: "tenant"},
	"DELETE /admin/v1/identity/department-mappings/{id}":  {Resource: "identity_sources", Action: "manage", ScopeType: "tenant"},
	"POST /admin/v1/identity/department-mappings/preview": {Resource: "identity_sources", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/identity/status":                       {Resource: "identity_sources", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/identity/overview":                     {Resource: "identity_sources", Action: "read", ScopeType: "tenant"},
	// Directory sources remain an independently authorized capability under the unified UI.
	"GET /admin/v1/directory/sources/draft":                   {Resource: "directory_sources", Action: "read", ScopeType: "tenant"},
	"PUT /admin/v1/directory/sources/draft":                   {Resource: "directory_sources", Action: "write", ScopeType: "tenant"},
	"POST /admin/v1/directory/sources/test":                   {Resource: "directory_sources", Action: "write", ScopeType: "tenant"},
	"POST /admin/v1/directory/sources/sync":                   {Resource: "directory_sources", Action: "manage", ScopeType: "tenant"},
	"POST /admin/v1/directory/sources/activate":               {Resource: "directory_sources", Action: "manage", ScopeType: "tenant"},
	"POST /admin/v1/directory/sources/disable":                {Resource: "directory_sources", Action: "manage", ScopeType: "tenant"},
	"POST /admin/v1/directory/sources/preview":                {Resource: "directory_sources", Action: "manage", ScopeType: "tenant"},
	"GET /admin/v1/directory/sources/previews/{id}":           {Resource: "directory_sources", Action: "read", ScopeType: "tenant"},
	"POST /admin/v1/directory/sources/previews/{id}/activate": {Resource: "directory_sources", Action: "manage", ScopeType: "tenant"},
	"GET /admin/v1/directory/sync-runs":                       {Resource: "directory_sources", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/directory/sync-runs/{id}":                  {Resource: "directory_sources", Action: "read", ScopeType: "tenant"},

	// W9 9.3 控制台 CAS/企业微信账号绑定（handler 另按目标账号角色做越级校验）

	// Audit chain
	"GET /admin/v1/audit-chain/stats":     {Resource: "audit_chain", Action: "read", ScopeType: "tenant"},
	"POST /admin/v1/audit-chain/verify":   {Resource: "audit_chain", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/audit-chain/integrity": {Resource: "audit_chain", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/audit-chain/export":    {Resource: "audit_chain", Action: "export", ScopeType: "tenant"},

	// Security events
	"GET /admin/v1/security/events": {Resource: "security_events", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/anomalies":       {Resource: "security_events", Action: "read", ScopeType: "tenant"},

	// Eval integration evidence API. These routes are protected by shared-secret auth,
	// but the static route coverage test still requires explicit permission metadata.
	"GET /admin/v1/eval-integration/health":                  {Resource: "security_events", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/eval-integration/verify-reciprocal":       {Resource: "security_events", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/eval-integration/audit-events":            {Resource: "security_events", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/eval-integration/audit-events/{id}":       {Resource: "security_events", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/eval-integration/assurance-contract":      {Resource: "security_events", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/eval-integration/assurance-evidence":      {Resource: "security_events", Action: "read", ScopeType: "tenant"},
	"POST /admin/v1/eval-integration/findings":               {Resource: "security_events", Action: "write", ScopeType: "tenant"},
	"POST /admin/v1/eval-integration/policy-suggestions":     {Resource: "security_events", Action: "write", ScopeType: "tenant"},
	"GET /admin/v1/eval-integration/policy-suggestions/{id}": {Resource: "security_events", Action: "read", ScopeType: "tenant"},

	// Portal integration (chat-portal backend). These routes are protected by shared-secret
	// auth (PortalIntegrationAPIMiddleware), but the static route coverage test still
	// requires explicit permission metadata. Resources mirror the session-route analogs.
	// Chat handoff redemption is additionally authenticated by the portal shared secret.
	"POST /admin/v1/portal-integration/chat-login/redeem":               {Resource: "identity_sources", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/portal-integration/employee-key":                     {Resource: "api_keys", Action: "read", ScopeType: "tenant"},
	"POST /admin/v1/portal-integration/employee-key/ensure":             {Resource: "api_keys", Action: "write", ScopeType: "tenant"},
	"POST /admin/v1/portal-integration/employee-key/claim":              {Resource: "api_keys", Action: "write", ScopeType: "tenant"},
	"POST /admin/v1/portal-integration/employee-key/reset":              {Resource: "api_keys", Action: "write", ScopeType: "tenant"},
	"GET /admin/v1/portal-integration/employee-key/credential":          {Resource: "api_keys", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/portal-integration/health":                           {Resource: "security_events", Action: "read", ScopeType: "tenant"},
	"POST /admin/v1/portal-integration/customer-keys/{id}/reset":        {Resource: "api_keys", Action: "write", ScopeType: "tenant"},
	"DELETE /admin/v1/portal-integration/customer-keys/{id}":            {Resource: "api_keys", Action: "delete", ScopeType: "tenant"},
	"PATCH /admin/v1/portal-integration/customer-keys/{id}":             {Resource: "api_keys", Action: "write", ScopeType: "tenant"},
	"GET /admin/v1/portal-integration/customer-keys":                    {Resource: "api_keys", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/portal-integration/client-config":                    {Resource: "system_settings", Action: "read", ScopeType: "tenant"},
	"POST /admin/v1/portal-integration/upload-events/legacy-index":      {Resource: "security_events", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/portal-integration/customer-billing":                 {Resource: "saving_metrics", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/portal-integration/model-prices":                     {Resource: "saving_metrics", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/portal-integration/model-performance":                {Resource: "saving_metrics", Action: "read", ScopeType: "tenant"},
	"POST /admin/v1/portal-integration/customer-keys/{id}/reveal":       {Resource: "api_keys", Action: "read", ScopeType: "tenant"},
	"PUT /admin/v1/portal-integration/customer-billing/limits":          {Resource: "saving_metrics", Action: "write", ScopeType: "tenant"},
	"POST /admin/v1/portal-integration/customer-billing/redemptions":    {Resource: "saving_metrics", Action: "write", ScopeType: "tenant"},
	"GET /admin/v1/portal-integration/group-mapping-rules":              {Resource: "group_mapping_rules", Action: "read", ScopeType: "tenant"},
	"POST /admin/v1/portal-integration/keys":                            {Resource: "api_keys", Action: "write", ScopeType: "tenant"},
	"GET /admin/v1/portal-integration/keys":                             {Resource: "api_keys", Action: "read", ScopeType: "tenant"},
	"POST /admin/v1/portal-integration/keys/{id}/revoke":                {Resource: "api_keys", Action: "write", ScopeType: "tenant"},
	"GET /admin/v1/portal-integration/usage/by-key":                     {Resource: "saving_metrics", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/portal-integration/usage/trend":                      {Resource: "saving_metrics", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/portal-integration/usage/by-model":                   {Resource: "saving_metrics", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/portal-integration/usage/summary":                    {Resource: "saving_metrics", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/portal-integration/teams/{id}/models":                {Resource: "models", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/portal-integration/teams/{id}/effective":             {Resource: "teams", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/portal-integration/policies/model":                   {Resource: "models", Action: "read", ScopeType: "tenant"},
	"PUT /admin/v1/portal-integration/policies/model":                   {Resource: "models", Action: "write", ScopeType: "tenant"},
	"GET /admin/v1/portal-integration/models":                           {Resource: "models", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/portal-integration/projects":                         {Resource: "projects", Action: "read", ScopeType: "tenant"},
	"POST /admin/v1/portal-integration/projects":                        {Resource: "projects", Action: "write", ScopeType: "tenant"},
	"GET /admin/v1/portal-integration/teams":                            {Resource: "teams", Action: "read", ScopeType: "tenant"},
	"POST /admin/v1/portal-integration/teams":                           {Resource: "teams", Action: "write", ScopeType: "tenant"},
	"POST /admin/v1/portal-integration/users":                           {Resource: "users", Action: "write", ScopeType: "tenant"},
	"GET /admin/v1/portal-integration/users/{id}/authorization-context": {Resource: "users", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/portal-integration/users/{id}/call-records":          {Resource: "security_events", Action: "read", ScopeType: "tenant"},
	"POST /admin/v1/portal-integration/teams/{id}/members":              {Resource: "teams", Action: "write", ScopeType: "tenant"},
	// 员工诊断助手：门户代调，调用身份固定为非管理员，只能查本人。
	"POST /admin/v1/portal-integration/diagnostics/sessions":               {Resource: "diagnostics", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/portal-integration/diagnostics/sessions":                {Resource: "diagnostics", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/portal-integration/diagnostics/sessions/{id}":           {Resource: "diagnostics", Action: "read", ScopeType: "tenant"},
	"POST /admin/v1/portal-integration/diagnostics/sessions/{id}/messages": {Resource: "diagnostics", Action: "read", ScopeType: "tenant"},

	"GET /admin/v1/portal-integration/audit-events":              {Resource: "security_events", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/portal-integration/policies/file":             {Resource: "security_events", Action: "read", ScopeType: "tenant"},
	"POST /admin/v1/portal-integration/upload-ingest":            {Resource: "security_events", Action: "write", ScopeType: "tenant"},
	"GET /admin/v1/portal-integration/upload-events":             {Resource: "security_events", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/portal-integration/system/chat-portal-status": {Resource: "security_events", Action: "read", ScopeType: "tenant"},

	// Saving / FX / Forecast
	"GET /admin/v1/savings/summary": {Resource: "saving_metrics", Action: "read", ScopeType: "tenant"},

	// Customer billing operations. Handler-level checks additionally restrict
	// this surface to platform administrators.
	// budget-tree 是配额策略 + 员工额度的只读视图：单位管理员原本就能读配额策略，处理器再限定只读本单位。
	"GET /admin/v1/billing/employee-settings":          {Resource: "billing_settings", Action: "read", ScopeType: "tenant"},
	"PUT /admin/v1/billing/employee-settings":          {Resource: "billing", Action: "write", ScopeType: "tenant"},
	"POST /admin/v1/billing/currency-switch":           {Resource: "billing_currency", Action: "write", ScopeType: "tenant"},
	"GET /admin/v1/billing/employee-allowances":        {Resource: "billing", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/billing/budget-tree":                {Resource: "quota_policies", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/billing/statements/monthly":         {Resource: "billing", Action: "read", ScopeType: "tenant"},
	"PUT /admin/v1/billing/employee-allowances":        {Resource: "billing", Action: "write", ScopeType: "tenant"},
	"GET /admin/v1/billing/upstream-models":            {Resource: "billing", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/billing/upstream-rates":             {Resource: "billing", Action: "read", ScopeType: "tenant"},
	"PUT /admin/v1/billing/upstream-rates":             {Resource: "billing", Action: "write", ScopeType: "tenant"},
	"DELETE /admin/v1/billing/upstream-rates":          {Resource: "billing", Action: "delete", ScopeType: "tenant"},
	"GET /admin/v1/billing/channel-fixed-costs":        {Resource: "billing", Action: "read", ScopeType: "tenant"},
	"PUT /admin/v1/billing/channel-fixed-costs":        {Resource: "billing", Action: "write", ScopeType: "tenant"},
	"DELETE /admin/v1/billing/channel-fixed-costs":     {Resource: "billing", Action: "delete", ScopeType: "tenant"},
	"PUT /admin/v1/billing/tariffs/{id}":               {Resource: "billing", Action: "write", ScopeType: "tenant"},
	"GET /admin/v1/billing/runtime":                    {Resource: "billing", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/billing/customers":                  {Resource: "billing", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/billing/pricing-capabilities":       {Resource: "billing", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/billing/models":                     {Resource: "billing", Action: "read", ScopeType: "tenant"},
	"PUT /admin/v1/billing/customers/{id}/group":       {Resource: "billing", Action: "write", ScopeType: "tenant"},
	"GET /admin/v1/billing/customer-groups":            {Resource: "billing", Action: "read", ScopeType: "tenant"},
	"POST /admin/v1/billing/customer-groups":           {Resource: "billing", Action: "write", ScopeType: "tenant"},
	"PATCH /admin/v1/billing/customer-groups/{id}":     {Resource: "billing", Action: "write", ScopeType: "tenant"},
	"POST /admin/v1/billing/wallets/credit":            {Resource: "billing", Action: "write", ScopeType: "tenant"},
	"POST /admin/v1/billing/wallets/adjustments":       {Resource: "billing", Action: "write", ScopeType: "tenant"},
	"GET /admin/v1/billing/ledger":                     {Resource: "billing", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/billing/prices":                     {Resource: "billing", Action: "read", ScopeType: "tenant"},
	"POST /admin/v1/billing/prices":                    {Resource: "billing", Action: "write", ScopeType: "tenant"},
	"POST /admin/v1/billing/prices/newapi-ratio":       {Resource: "billing", Action: "write", ScopeType: "tenant"},
	"GET /admin/v1/billing/tariffs":                    {Resource: "billing", Action: "read", ScopeType: "tenant"},
	"POST /admin/v1/billing/tariffs":                   {Resource: "billing", Action: "write", ScopeType: "tenant"},
	"DELETE /admin/v1/billing/tariffs/{id}":            {Resource: "billing", Action: "delete", ScopeType: "tenant"},
	"POST /admin/v1/billing/tariffs/{id}/publish":      {Resource: "billing", Action: "write", ScopeType: "tenant"},
	"POST /admin/v1/billing/tariffs/{id}/retire":       {Resource: "billing", Action: "write", ScopeType: "tenant"},
	"GET /admin/v1/billing/tariffs/preview":            {Resource: "billing", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/billing/redemptions/export":         {Resource: "billing", Action: "read", ScopeType: "tenant"},
	"POST /admin/v1/billing/redemptions/{id}/reveal":   {Resource: "billing", Action: "write", ScopeType: "tenant"},
	"GET /admin/v1/billing/redemptions/{id}":           {Resource: "billing", Action: "read", ScopeType: "tenant"},
	"POST /admin/v1/billing/redemptions/batch-disable": {Resource: "billing", Action: "write", ScopeType: "tenant"},
	"GET /admin/v1/billing/redemptions":                {Resource: "billing", Action: "read", ScopeType: "tenant"},
	"POST /admin/v1/billing/redemptions":               {Resource: "billing", Action: "write", ScopeType: "tenant"},
	"DELETE /admin/v1/billing/redemptions/{id}":        {Resource: "billing", Action: "write", ScopeType: "tenant"},
	"PATCH /admin/v1/billing/redemptions/{id}":         {Resource: "billing", Action: "write", ScopeType: "tenant"},

	// W7 7.5: operator-verified cache breakdown for a recovered charge.

	"GET /admin/v1/savings/project-breakdown": {Resource: "saving_metrics", Action: "read", ScopeType: "tenant"},
	"PUT /admin/v1/fx":                        {Resource: "fx_rates", Action: "write", ScopeType: "tenant"},
	"GET /admin/v1/fx":                        {Resource: "fx_rates", Action: "read", ScopeType: "tenant"},
	"POST /admin/v1/forecast/jobs":            {Resource: "forecast_jobs", Action: "write", ScopeType: "tenant"},
	"GET /admin/v1/forecast/jobs":             {Resource: "forecast_jobs", Action: "read", ScopeType: "tenant"},

	// Routing policies
	"GET /admin/v1/model-routing":                        {Resource: "routing_policies", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/model-routing/status":                 {Resource: "routing_policies", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/model-routing/routes":                 {Resource: "routing_policies", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/model-routing/models":                 {Resource: "routing_policies", Action: "read", ScopeType: "tenant"},
	"POST /admin/v1/model-routing/validate":              {Resource: "routing_policies", Action: "read", ScopeType: "tenant"},
	"PUT /admin/v1/model-routing/default":                {Resource: "routing_policies", Action: "write", ScopeType: "tenant"},
	"DELETE /admin/v1/model-routing/default":             {Resource: "routing_policies", Action: "write", ScopeType: "tenant"},
	"PUT /admin/v1/model-routing/models/{model_name}":    {Resource: "routing_policies", Action: "write", ScopeType: "tenant"},
	"PUT /admin/v1/model-routing/models/*":               {Resource: "routing_policies", Action: "write", ScopeType: "tenant"},
	"DELETE /admin/v1/model-routing/models/{model_name}": {Resource: "routing_policies", Action: "write", ScopeType: "tenant"},
	"DELETE /admin/v1/model-routing/models/*":            {Resource: "routing_policies", Action: "write", ScopeType: "tenant"},
	"GET /admin/v1/routing-policies":                     {Resource: "routing_policies", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/routing-decisions":                    {Resource: "routing_policies", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/routing-decisions/{request_id}":       {Resource: "routing_policies", Action: "read", ScopeType: "tenant"},
	"POST /admin/v1/routing-policies":                    {Resource: "routing_policies", Action: "write", ScopeType: "tenant"},
	"PUT /admin/v1/routing-policies/{id}":                {Resource: "routing_policies", Action: "write", ScopeType: "tenant"},
	"DELETE /admin/v1/routing-policies/{id}":             {Resource: "routing_policies", Action: "delete", ScopeType: "tenant"},

	// Notify channels
	"GET /admin/v1/notify/channels":         {Resource: "notify_channels", Action: "read", ScopeType: "tenant"},
	"POST /admin/v1/notify/channels":        {Resource: "notify_channels", Action: "write", ScopeType: "tenant"},
	"PATCH /admin/v1/notify/channels/{id}":  {Resource: "notify_channels", Action: "write", ScopeType: "tenant"},
	"DELETE /admin/v1/notify/channels/{id}": {Resource: "notify_channels", Action: "delete", ScopeType: "tenant"},

	// Alert inbox
	"GET /admin/v1/alerts":                     {Resource: "alert_inbox", Action: "read", ScopeType: "tenant"},
	"PATCH /admin/v1/alerts/{id}":              {Resource: "alert_inbox", Action: "write", ScopeType: "tenant"},
	"GET /admin/v1/alerts/inbox":               {Resource: "alert_inbox", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/alerts/inbox/export":        {Resource: "alert_inbox", Action: "read", ScopeType: "tenant"},
	"POST /admin/v1/alerts/{id}/read":          {Resource: "alert_inbox", Action: "write", ScopeType: "tenant"},
	"GET /admin/v1/alert-groups":               {Resource: "alert_groups", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/alert-groups/{id}":          {Resource: "alert_groups", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/alert-groups/{id}/events":   {Resource: "alert_groups", Action: "read", ScopeType: "tenant"},
	"PATCH /admin/v1/alert-groups/{id}":        {Resource: "alert_groups", Action: "write", ScopeType: "tenant"},
	"POST /admin/v1/alert-groups/batch-status": {Resource: "alert_groups", Action: "write", ScopeType: "tenant"},

	// 消息中心折叠视图（读）与管理员专用的类别汇总 / 批量已读（SoD 归系统类，handler 再校验控制台管理员）。
	"GET /admin/v1/alerts/inbox/folded":            {Resource: "alert_inbox", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/alerts/inbox/folded/items":      {Resource: "alert_inbox", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/alerts/inbox/type-summary":      {Resource: "alert_inbox", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/alerts/inbox/bulk-read/preview": {Resource: "alert_inbox", Action: "read", ScopeType: "tenant"},
	"POST /admin/v1/alerts/inbox/bulk-read":        {Resource: "alert_inbox", Action: "write", ScopeType: "tenant"},

	// Budget / pause
	"POST /admin/v1/budgets/keys/{key}/pause":          {Resource: "api_keys", Action: "write", ScopeType: "tenant"},
	"POST /admin/v1/budgets/keys/{key}/resume":         {Resource: "api_keys", Action: "write", ScopeType: "tenant"},
	"GET /admin/v1/budgets/snapshot":                   {Resource: "saving_metrics", Action: "read", ScopeType: "tenant"},
	"POST /admin/v1/budgets/keys/{key_prefix}/pause":   {Resource: "api_keys", Action: "write", ScopeType: "tenant"},
	"POST /admin/v1/budgets/keys/{key_prefix}/unpause": {Resource: "api_keys", Action: "write", ScopeType: "tenant"},
	"GET /admin/v1/budgets/pause-log":                  {Resource: "api_keys", Action: "read", ScopeType: "tenant"},

	// Billing/health real read models (feat/billing-readmodels-20261002).
	"GET /admin/v1/budgets/keys/{key_id}/readmodel": {Resource: "saving_metrics", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/service-health/readmodel":        {Resource: "security_events", Action: "read", ScopeType: "tenant"},

	// 运维诊断机器人：员工可发起/查看自己的诊断（read）；诊断包导出与设置修改需要 write（管理员）。
	"POST /admin/v1/diagnostics/sessions":               {Resource: "diagnostics", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/diagnostics/sessions":                {Resource: "diagnostics", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/diagnostics/sessions/{id}":           {Resource: "diagnostics", Action: "read", ScopeType: "tenant"},
	"POST /admin/v1/diagnostics/sessions/{id}/messages": {Resource: "diagnostics", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/diagnostics/sessions/{id}/bundle":    {Resource: "diagnostics", Action: "write", ScopeType: "tenant"},
	"GET /admin/v1/diagnostics/settings":                {Resource: "diagnostics", Action: "read", ScopeType: "tenant"},
	"PUT /admin/v1/diagnostics/settings":                {Resource: "diagnostics", Action: "write", ScopeType: "tenant"},
	"GET /admin/v1/diagnostics/badge":                   {Resource: "diagnostics", Action: "read", ScopeType: "tenant"},

	// Settings / auth session
	"POST /admin/v1/logout":             {Resource: "users", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/settings/org-labels": {Resource: "users", Action: "read", ScopeType: "tenant"},
	"PUT /admin/v1/settings/org-labels": {Resource: "users", Action: "write", ScopeType: "tenant"},

	// Tenant scoped cross-unit read / admin
	"GET /admin/v1/tenants/{id}/teams":                   {Resource: "teams", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/tenants/{id}/users":                   {Resource: "users", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/tenants/{id}/projects":                {Resource: "projects", Action: "read", ScopeType: "tenant"},
	"DELETE /admin/v1/tenants/{id}/projects/{projectId}": {Resource: "projects", Action: "delete", ScopeType: "tenant"},
	"GET /admin/v1/tenants/{id}/keys":                    {Resource: "api_keys", Action: "read", ScopeType: "tenant"},
	"DELETE /admin/v1/tenants/{id}":                      {Resource: "users", Action: "delete", ScopeType: "tenant"},

	// Security rules / detectors
	"GET /admin/v1/policy-suggestions":                       {Resource: "security_events", Action: "read", ScopeType: "tenant"},
	"POST /admin/v1/policy-suggestions/{id}/approve":         {Resource: "security_events", Action: "write", ScopeType: "tenant"},
	"POST /admin/v1/policy-suggestions/{id}/reject":          {Resource: "security_events", Action: "write", ScopeType: "tenant"},
	"GET /admin/v1/rule-sets":                                {Resource: "security_events", Action: "read", ScopeType: "tenant"},
	"POST /admin/v1/rule-sets":                               {Resource: "security_events", Action: "write", ScopeType: "tenant"},
	"POST /admin/v1/rule-sets/{id}/publish":                  {Resource: "security_events", Action: "write", ScopeType: "tenant"},
	"POST /admin/v1/security/test":                           {Resource: "security_events", Action: "read", ScopeType: "tenant"},
	"POST /admin/v1/security/semantic/test-judge":            {Resource: "security_events", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/security/semantic/settings":               {Resource: "security_events", Action: "read", ScopeType: "tenant"},
	"PUT /admin/v1/security/semantic/settings":               {Resource: "security_events", Action: "write", ScopeType: "tenant"},
	"PUT /admin/v1/security/system-settings":                 {Resource: "security_events", Action: "write", ScopeType: "tenant"},
	"GET /admin/v1/security/semantic/runtime-status":         {Resource: "system_config", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/security/posture":                         {Resource: "system_config", Action: "read", ScopeType: "tenant"},
	"GET /api/security/posture":                              {Resource: "system_config", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/security/reply-policy":                    {Resource: "security_events", Action: "read", ScopeType: "tenant"},
	"PUT /admin/v1/security/reply-policy":                    {Resource: "security_events", Action: "write", ScopeType: "tenant"},
	"GET /admin/v1/security/smart-detection/overview":        {Resource: "security_events", Action: "read", ScopeType: "tenant"},
	"PUT /admin/v1/security/smart-detection/config":          {Resource: "security_events", Action: "write", ScopeType: "tenant"},
	"GET /admin/v1/security/policy-assets":                   {Resource: "security_events", Action: "read", ScopeType: "tenant"},
	"PUT /admin/v1/security/policy-assets/{id}":              {Resource: "security_events", Action: "write", ScopeType: "tenant"},
	"GET /admin/v1/security/policies":                        {Resource: "security_events", Action: "read", ScopeType: "tenant"},
	"POST /admin/v1/security/policies":                       {Resource: "security_events", Action: "write", ScopeType: "tenant"},
	"GET /admin/v1/security/policies/capabilities":           {Resource: "security_events", Action: "read", ScopeType: "tenant"},
	"POST /admin/v1/security/policies/preview":               {Resource: "security_events", Action: "read", ScopeType: "tenant"},
	"POST /admin/v1/security/policies/quick-create/generate": {Resource: "security_events", Action: "write", ScopeType: "tenant"},
	"POST /admin/v1/security/policies/quick-create/preview":  {Resource: "security_events", Action: "write", ScopeType: "tenant"},
	"POST /admin/v1/security/policies/batch":                 {Resource: "security_events", Action: "write", ScopeType: "tenant"},
	"PATCH /admin/v1/security/policies/{id}":                 {Resource: "security_events", Action: "write", ScopeType: "tenant"},
	"DELETE /admin/v1/security/policies/{id}":                {Resource: "security_events", Action: "write", ScopeType: "tenant"},
	"GET /admin/v1/rules":                                    {Resource: "security_events", Action: "read", ScopeType: "tenant"},
	"POST /admin/v1/rules":                                   {Resource: "security_events", Action: "write", ScopeType: "tenant"},
	"PATCH /admin/v1/rules/{id}":                             {Resource: "security_events", Action: "write", ScopeType: "tenant"},
	"DELETE /admin/v1/rules/{id}":                            {Resource: "security_events", Action: "delete", ScopeType: "tenant"},
	"POST /admin/v1/rules/{id}/toggle":                       {Resource: "security_events", Action: "write", ScopeType: "tenant"},
	"GET /admin/v1/rules/pull-status":                        {Resource: "security_events", Action: "read", ScopeType: "tenant"},
	"POST /admin/v1/detectors/batch-update":                  {Resource: "security_events", Action: "write", ScopeType: "tenant"},
	"POST /admin/v1/detectors/init":                          {Resource: "security_events", Action: "write", ScopeType: "tenant"},
	"GET /admin/v1/content-security/rules":                   {Resource: "security_events", Action: "read", ScopeType: "tenant"},
	"POST /admin/v1/content-security/rules":                  {Resource: "security_events", Action: "write", ScopeType: "tenant"},
	"GET /admin/v1/content-security/exceptions":              {Resource: "security_events", Action: "read", ScopeType: "tenant"},
	"POST /admin/v1/content-security/exceptions":             {Resource: "security_events", Action: "write", ScopeType: "tenant"},
	"DELETE /admin/v1/content-security/exceptions/{id}":      {Resource: "security_events", Action: "write", ScopeType: "tenant"},
	"GET /admin/v1/content-security/file-policy":             {Resource: "security_events", Action: "read", ScopeType: "tenant"},
	"PUT /admin/v1/content-security/file-policy":             {Resource: "security_events", Action: "write", ScopeType: "tenant"},
	"GET /admin/v1/content-security/industry":                {Resource: "security_events", Action: "read", ScopeType: "tenant"},
	"PUT /admin/v1/content-security/industry":                {Resource: "security_events", Action: "write", ScopeType: "tenant"},

	// Audit / usage / statistics
	"GET /admin/v1/audit/requests":                                 {Resource: "security_events", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/audit/requests/{request_id}":                    {Resource: "security_events", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/audit/events":                                   {Resource: "security_events", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/integration/capabilities":                       {Resource: "integration", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/security/alert-occurrences":                     {Resource: "security_events", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/security/block-records":                         {Resource: "security_events", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/security/block-records/export":                  {Resource: "security_events", Action: "export", ScopeType: "tenant"},
	"GET /admin/v1/security/block-records/{block_id}":              {Resource: "security_events", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/security/block-records/{block_id}/trace":        {Resource: "security_events", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/security/alert-occurrences/summary":             {Resource: "security_events", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/security/alert-occurrences/operational":         {Resource: "security_events", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/security/alert-occurrences/operational/summary": {Resource: "security_events", Action: "read", ScopeType: "tenant"},
	// 告警案件物化表的诊断状态：处理函数里只放平台管理员，这里按系统配置读归类。
	"GET /admin/v1/security/alert-occurrences/store-status":      {Resource: "system_config", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/audit/dispositions":                           {Resource: "security_events", Action: "read", ScopeType: "tenant"},
	"PUT /admin/v1/audit/dispositions":                           {Resource: "audit_dispositions", Action: "write", ScopeType: "tenant"},
	"GET /admin/v1/audit/export":                                 {Resource: "security_events", Action: "export", ScopeType: "tenant"},
	"GET /admin/v1/audit/content":                                {Resource: "security_events", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/audit/content/security-overview":              {Resource: "security_events", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/audit/content/users":                          {Resource: "security_events", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/audit/content/{session_id}":                   {Resource: "security_events", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/audit/content/{session_id}/events":            {Resource: "security_events", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/audit/content/{session_id}/export":            {Resource: "security_events", Action: "export", ScopeType: "tenant"},
	"GET /admin/v1/usage/summary":                                {Resource: "saving_metrics", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/usage/by-project":                             {Resource: "saving_metrics", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/usage/cost-coverage":                          {Resource: "saving_metrics", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/usage/by-model":                               {Resource: "saving_metrics", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/usage/by-user":                                {Resource: "saving_metrics", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/usage/by-key":                                 {Resource: "saving_metrics", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/usage/by-provider":                            {Resource: "saving_metrics", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/usage/trend":                                  {Resource: "saving_metrics", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/usage/records":                                {Resource: "saving_metrics", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/usage/records/summary":                        {Resource: "saving_metrics", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/usage/recommendations":                        {Resource: "saving_metrics", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/billing/analytics/summary":                    {Resource: "saving_metrics", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/billing/analytics/breakdown":                  {Resource: "saving_metrics", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/billing/analytics/series":                     {Resource: "saving_metrics", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/billing/analytics/time-profile":               {Resource: "saving_metrics", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/billing/analytics/department-provider-matrix": {Resource: "saving_metrics", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/billing/analytics/report":                     {Resource: "saving_metrics", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/users/{user_id}/usage/summary":                {Resource: "saving_metrics", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/users/{user_id}/usage/trend":                  {Resource: "saving_metrics", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/users/{user_id}/usage/by-model":               {Resource: "saving_metrics", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/users/{user_id}/usage/records":                {Resource: "saving_metrics", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/agent-identities":                             {Resource: "security_events", Action: "read", ScopeType: "tenant"},
	"POST /admin/v1/agent-identities":                            {Resource: "audit_dispositions", Action: "write", ScopeType: "tenant"},
	"GET /admin/v1/agent-sessions":                               {Resource: "saving_metrics", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/agent-sessions/stats":                         {Resource: "saving_metrics", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/agent-sessions/distribution":                  {Resource: "saving_metrics", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/agent-sessions/by-type":                       {Resource: "saving_metrics", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/agent-sessions/{session_id}":                  {Resource: "saving_metrics", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/stats/overview":                               {Resource: "saving_metrics", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/stats/org":                                    {Resource: "saving_metrics", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/stats/users":                                  {Resource: "saving_metrics", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/stats/apps":                                   {Resource: "saving_metrics", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/stats/models":                                 {Resource: "saving_metrics", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/stats/agents":                                 {Resource: "saving_metrics", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/stats/agents/distribution":                    {Resource: "saving_metrics", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/audit/agents/user/{user_id}":                  {Resource: "saving_metrics", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/audit/agents/sessions":                        {Resource: "saving_metrics", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/audit/tools/stats":                            {Resource: "security_events", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/audit/tools/high-risk":                        {Resource: "security_events", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/audit/tools/session/{session_id}":             {Resource: "security_events", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/audit/tools/user/{user_id}":                   {Resource: "security_events", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/audit/tools/trend":                            {Resource: "security_events", Action: "read", ScopeType: "tenant"},

	// AgentGuard policy governance
	"GET /admin/v1/agentguard/policies":                    {Resource: "agentguard_policies", Action: "read", ScopeType: "tenant"},
	"POST /admin/v1/agentguard/policies":                   {Resource: "agentguard_policies", Action: "write", ScopeType: "tenant"},
	"PUT /admin/v1/agentguard/policies/{id}":               {Resource: "agentguard_policies", Action: "write", ScopeType: "tenant"},
	"GET /admin/v1/agentguard/templates":                   {Resource: "agentguard_policies", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/agentguard/governance/stats":            {Resource: "agentguard_policies", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/agentguard/risk-overview":               {Resource: "agentguard_policies", Action: "read", ScopeType: "tenant"},
	"POST /admin/v1/agentguard/policies/simulate":          {Resource: "agentguard_policies", Action: "write", ScopeType: "tenant"},
	"GET /admin/v1/agentguard/policies/{id}/versions":      {Resource: "agentguard_policies", Action: "read", ScopeType: "tenant"},
	"POST /admin/v1/agentguard/policies/{id}/rollback":     {Resource: "agentguard_policies", Action: "write", ScopeType: "tenant"},
	"GET /admin/v1/agentguard/exceptions":                  {Resource: "agentguard_policies", Action: "read", ScopeType: "tenant"},
	"POST /admin/v1/agentguard/exceptions":                 {Resource: "agentguard_policies", Action: "write", ScopeType: "tenant"},
	"DELETE /admin/v1/agentguard/exceptions/{id}":          {Resource: "agentguard_policies", Action: "write", ScopeType: "tenant"},
	"POST /admin/v1/agentguard/exceptions/suggest":         {Resource: "agentguard_policies", Action: "write", ScopeType: "tenant"},
	"GET /admin/v1/agentguard/confirmations":               {Resource: "agentguard_policies", Action: "read", ScopeType: "tenant"},
	"POST /admin/v1/agentguard/confirmations/{id}/resolve": {Resource: "agentguard_policies", Action: "write", ScopeType: "tenant"},
	"GET /admin/v1/agent/approvals":                        {Resource: "agent_principals", Action: "read", ScopeType: "tenant"},
	"POST /admin/v1/agent/approvals/{id}/resolve":          {Resource: "agent_principals", Action: "admin", ScopeType: "tenant"},
	"POST /admin/v1/agent/approvals/{id}/revoke":           {Resource: "agent_principals", Action: "admin", ScopeType: "tenant"},
	"GET /admin/v1/agent/approval-exceptions":              {Resource: "agent_principals", Action: "read", ScopeType: "tenant"},
	"POST /admin/v1/agent/approval-exceptions":             {Resource: "agent_principals", Action: "admin", ScopeType: "tenant"},
	"DELETE /admin/v1/agent/approval-exceptions/{id}":      {Resource: "agent_principals", Action: "admin", ScopeType: "tenant"},
	"GET /admin/v1/agentguard/behavior/baseline":           {Resource: "agentguard_policies", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/agentguard/rollouts":                    {Resource: "agentguard_policies", Action: "read", ScopeType: "tenant"},
	"POST /admin/v1/agentguard/rollouts":                   {Resource: "agentguard_policies", Action: "write", ScopeType: "tenant"},

	// Agent destructive-operation policy and customer event projections.
	"GET /admin/v1/agent-operation-protection":               {Resource: "agent_operation_policy", Action: "read", ScopeType: "tenant"},
	"PUT /admin/v1/agent-operation-protection":               {Resource: "agent_operation_policy", Action: "write", ScopeType: "tenant"},
	"GET /admin/v1/agent-operation-events":                   {Resource: "agent_operation_event", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/agent-operation-events/{public_event_id}": {Resource: "agent_operation_event", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/agent-operation-events/{id}":              {Resource: "agent_operation_event", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/policy-center/agent-behaviors":            {Resource: "agent_operation_policy", Action: "read", ScopeType: "tenant"},
	"PUT /admin/v1/policy-center/agent-behaviors/{key}":      {Resource: "agent_operation_policy", Action: "write", ScopeType: "tenant"},
	"GET /admin/v1/protection-settings":                      {Resource: "agent_operation_policy", Action: "read", ScopeType: "tenant"},
	"PUT /admin/v1/protection-settings":                      {Resource: "agent_operation_policy", Action: "write", ScopeType: "tenant"},

	// Platform/system management routes with handler-level role guards.
	"GET /admin/v1/tools/config":                                                         {Resource: "security_events", Action: "read", ScopeType: "tenant"},
	"POST /admin/v1/tools/config":                                                        {Resource: "security_events", Action: "write", ScopeType: "tenant"},
	"PUT /admin/v1/tools/config/{id}":                                                    {Resource: "security_events", Action: "write", ScopeType: "tenant"},
	"DELETE /admin/v1/tools/config/{id}":                                                 {Resource: "security_events", Action: "delete", ScopeType: "tenant"},
	"POST /admin/v1/tools/config/batch":                                                  {Resource: "security_events", Action: "write", ScopeType: "tenant"},
	"GET /admin/v1/audit/access-retention":                                               {Resource: "security_events", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/audit/access-retention/runs":                                          {Resource: "security_events", Action: "read", ScopeType: "tenant"},
	"POST /admin/v1/audit/leak-trace":                                                    {Resource: "security_events", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/audit/access-retention/export":                                        {Resource: "security_events", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/audit/access-retention/{request_id}/timeline":                         {Resource: "security_events", Action: "read", ScopeType: "tenant"},
	"POST /admin/v1/audit/access-retention/{request_id}/timeline":                        {Resource: "security_events", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/audit/raw-evidence":                                                   {Resource: "security_events", Action: "read", ScopeType: "tenant"},
	"POST /admin/v1/audit/raw-evidence/{id}/reveal":                                      {Resource: "security_events", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/audit/raw-evidence/settings":                                          {Resource: "security_events", Action: "read", ScopeType: "tenant"},
	"PUT /admin/v1/audit/raw-evidence/settings":                                          {Resource: "security_events", Action: "write", ScopeType: "tenant"},
	"GET /admin/v1/audit/access-retention/{request_id}/content":                          {Resource: "security_events", Action: "read", ScopeType: "tenant"},
	"POST /admin/v1/audit/access-retention/{request_id}/content":                         {Resource: "security_events", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/audit/access-retention/{request_id}/image-proxy":                      {Resource: "security_events", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/audit/access-retention/{request_id}/blob":                             {Resource: "security_events", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/audit/access-retention/{request_id}/artifacts/{artifact_id}/preview":  {Resource: "security_events", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/audit/access-retention/{request_id}/artifacts/{artifact_id}/original": {Resource: "security_events", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/proxy/forward-access":                                                 {Resource: "security_events", Action: "read", ScopeType: "tenant"},
	// Content-retention storage backend config (configures the access-retention subsystem above)
	"GET /admin/v1/retention/storage-config":         {Resource: "security_events", Action: "read", ScopeType: "tenant"},
	"PUT /admin/v1/retention/storage-config":         {Resource: "security_events", Action: "write", ScopeType: "tenant"},
	"POST /admin/v1/retention/storage-config/test":   {Resource: "security_events", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/llm-provider-catalog":             {Resource: "providers", Action: "read", ScopeType: "tenant"},
	"POST /admin/v1/llm-provider-catalog/test-match": {Resource: "providers", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/proxy/whitelist":                  {Resource: "providers", Action: "read", ScopeType: "tenant"},
	"POST /admin/v1/proxy/whitelist":                 {Resource: "providers", Action: "write", ScopeType: "tenant"},
	"PUT /admin/v1/proxy/whitelist/{id}":             {Resource: "providers", Action: "write", ScopeType: "tenant"},
	"DELETE /admin/v1/proxy/whitelist/{id}":          {Resource: "providers", Action: "delete", ScopeType: "tenant"},
	"GET /admin/v1/reverse-proxy/routes":             {Resource: "providers", Action: "read", ScopeType: "tenant"},
	"POST /admin/v1/reverse-proxy/routes":            {Resource: "providers", Action: "write", ScopeType: "tenant"},
	"PUT /admin/v1/reverse-proxy/routes/{id}":        {Resource: "providers", Action: "write", ScopeType: "tenant"},
	"DELETE /admin/v1/reverse-proxy/routes/{id}":     {Resource: "providers", Action: "delete", ScopeType: "tenant"},
	"POST /admin/v1/ca/generate":                     {Resource: "providers", Action: "write", ScopeType: "tenant"},
	"GET /admin/v1/ca/certificate":                   {Resource: "providers", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/ca/download":                      {Resource: "providers", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/ca/{id}/download":                 {Resource: "providers", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/ca/list":                          {Resource: "providers", Action: "read", ScopeType: "tenant"},
	"POST /admin/v1/ca/{id}/activate":                {Resource: "providers", Action: "write", ScopeType: "tenant"},
	"DELETE /admin/v1/ca/{id}":                       {Resource: "providers", Action: "delete", ScopeType: "tenant"},
	"GET /admin/v1/system/settings":                  {Resource: "system_config", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/system/initialization":            {Resource: "system_config", Action: "read", ScopeType: "tenant"},
	"POST /admin/v1/system/initialization/retry":     {Resource: "system_config", Action: "write", ScopeType: "tenant"},
	"PUT /admin/v1/system/settings":                  {Resource: "users", Action: "write", ScopeType: "tenant"},
	"POST /admin/v1/system/lse/test":                 {Resource: "users", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/system/license":                   {Resource: "system_license", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/system/license/host-info":         {Resource: "system_license", Action: "read", ScopeType: "tenant"},
	"POST /admin/v1/system/license/import":           {Resource: "system_license", Action: "write", ScopeType: "tenant"},
	"POST /admin/v1/system/license/trial":            {Resource: "system_license", Action: "write", ScopeType: "tenant"},
	"GET /admin/v1/system/audit-operations":          {Resource: "audit_chain", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/system/audit-operations/export":   {Resource: "audit_chain", Action: "export", ScopeType: "tenant"},
	"GET /admin/v1/system/product":                   {Resource: "system_config", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/system/version":                   {Resource: "users", Action: "read", ScopeType: "tenant"},
	"POST /admin/v1/system/upgrade/check":            {Resource: "users", Action: "write", ScopeType: "tenant"},
	"POST /admin/v1/system/upgrade/upload":           {Resource: "users", Action: "write", ScopeType: "tenant"},
	"POST /admin/v1/system/upgrade/execute":          {Resource: "users", Action: "write", ScopeType: "tenant"},
	"POST /admin/v1/system/upgrade/rollback":         {Resource: "users", Action: "write", ScopeType: "tenant"},
	"GET /admin/v1/system/upgrade/history":           {Resource: "users", Action: "read", ScopeType: "tenant"},
	"POST /admin/v1/system/ruleset/sync":             {Resource: "security_events", Action: "write", ScopeType: "tenant"},

	// Enterprise IAM extensions
	"DELETE /admin/v1/teams/{id}/members/{user_id}": {Resource: "teams.members", Action: "delete", ScopeType: "team", ScopeIDSource: "url:id"},
	"POST /admin/v1/teams/{id}/members/batch":       {Resource: "teams.members", Action: "write", ScopeType: "team", ScopeIDSource: "url:id"},
	"PUT /admin/v1/teams/{id}/budget":               {Resource: "quota_policies", Action: "write", ScopeType: "team", ScopeIDSource: "url:id"},
	"GET /admin/v1/teams/{id}/models":               {Resource: "models", Action: "read", ScopeType: "team", ScopeIDSource: "url:id"},
	"PUT /admin/v1/teams/{id}/models":               {Resource: "models", Action: "write", ScopeType: "team", ScopeIDSource: "url:id"},
	"DELETE /admin/v1/teams/{id}/models/{model_id}": {Resource: "models", Action: "delete", ScopeType: "team", ScopeIDSource: "url:id"},
	"GET /admin/v1/teams/{id}/effective":            {Resource: "teams", Action: "read", ScopeType: "team", ScopeIDSource: "url:id"},
	"GET /admin/v1/teams/{id}/projects":             {Resource: "projects", Action: "read", ScopeType: "team", ScopeIDSource: "url:id"},
	"GET /admin/v1/teams/{id}/usage":                {Resource: "saving_metrics", Action: "read", ScopeType: "team", ScopeIDSource: "url:id"},
	"PATCH /admin/v1/projects/{id}/team":            {Resource: "projects", Action: "write", ScopeType: "project", ScopeIDSource: "url:id"},
	"PATCH /admin/v1/users/{id}/personal-budget":    {Resource: "quota_policies", Action: "write", ScopeType: "tenant"},

	// Cost governance extensions
	"GET /admin/v1/fx/current":                     {Resource: "fx_rates", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/fx/history":                     {Resource: "fx_rates", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/savings/trend":                  {Resource: "saving_metrics", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/savings/config":                 {Resource: "saving_metrics", Action: "read", ScopeType: "tenant"},
	"PUT /admin/v1/savings/config":                 {Resource: "saving_metrics", Action: "write", ScopeType: "tenant"},
	"GET /admin/v1/notify-channels":                {Resource: "notify_channels", Action: "read", ScopeType: "tenant"},
	"POST /admin/v1/notify-channels":               {Resource: "notify_channels", Action: "write", ScopeType: "tenant"},
	"PUT /admin/v1/notify-channels/{id}":           {Resource: "notify_channels", Action: "write", ScopeType: "tenant"},
	"DELETE /admin/v1/notify-channels/{id}":        {Resource: "notify_channels", Action: "delete", ScopeType: "tenant"},
	"POST /admin/v1/notify-channels/{id}/test":     {Resource: "notify_channels", Action: "write", ScopeType: "tenant"},
	"GET /admin/v1/proxy-access-keys":              {Resource: "proxy_access_keys", Action: "read", ScopeType: "tenant"},
	"POST /admin/v1/proxy-access-keys":             {Resource: "proxy_access_keys", Action: "write", ScopeType: "tenant"},
	"PUT /admin/v1/proxy-access-keys/{id}":         {Resource: "proxy_access_keys", Action: "write", ScopeType: "tenant"},
	"DELETE /admin/v1/proxy-access-keys/{id}":      {Resource: "proxy_access_keys", Action: "delete", ScopeType: "tenant"},
	"POST /admin/v1/proxy-access-keys/{id}/rotate": {Resource: "proxy_access_keys", Action: "write", ScopeType: "tenant"},
	"GET /admin/v1/mcp-servers":                    {Resource: "mcp_servers", Action: "read", ScopeType: "tenant"},
	"POST /admin/v1/mcp-servers":                   {Resource: "mcp_servers", Action: "write", ScopeType: "tenant"},
	"PUT /admin/v1/mcp-servers/{id}":               {Resource: "mcp_servers", Action: "write", ScopeType: "tenant"},
	"DELETE /admin/v1/mcp-servers/{id}":            {Resource: "mcp_servers", Action: "delete", ScopeType: "tenant"},
	// MCP 安全网关：sync/tools 复用 mcp_servers 资源；策略用新资源 mcp_policies（seed.go 同步授权，双注册缺一不可）
	"POST /admin/v1/mcp-servers/{id}/sync":            {Resource: "mcp_servers", Action: "write", ScopeType: "tenant"},
	"POST /admin/v1/mcp-servers/{id}/test-connection": {Resource: "mcp_servers", Action: "write", ScopeType: "tenant"},
	"GET /admin/v1/mcp-servers/{id}/tools":            {Resource: "mcp_servers", Action: "read", ScopeType: "tenant"},
	"POST /admin/v1/mcp-servers/{id}/admission":       {Resource: "mcp_servers", Action: "write", ScopeType: "tenant"},
	"POST /admin/v1/mcp-tools/{id}/admission":         {Resource: "mcp_servers", Action: "write", ScopeType: "tenant"},
	"GET /admin/v1/mcp-tools/shadow-check":            {Resource: "mcp_servers", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/mcp-policies":                      {Resource: "mcp_policies", Action: "read", ScopeType: "tenant"},
	"POST /admin/v1/mcp-policies":                     {Resource: "mcp_policies", Action: "write", ScopeType: "tenant"},
	// 预演/遮蔽检测=只读（read 已授 tenant_admin/owner/auditor），零 DB 写入
	"POST /admin/v1/mcp-policies/simulate":     {Resource: "mcp_policies", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/mcp-policies/shadow-check":  {Resource: "mcp_policies", Action: "read", ScopeType: "tenant"},
	"POST /admin/v1/mcp-policies/shadow-check": {Resource: "mcp_policies", Action: "read", ScopeType: "tenant"},
	"PUT /admin/v1/mcp-policies/{id}":          {Resource: "mcp_policies", Action: "write", ScopeType: "tenant"},
	"DELETE /admin/v1/mcp-policies/{id}":       {Resource: "mcp_policies", Action: "delete", ScopeType: "tenant"},
	// 内置红线处置配置：读=mcp_policies:read，改=mcp_policies:write（handler 内另校验管理员角色）
	"GET /admin/v1/mcp-redline-settings": {Resource: "mcp_policies", Action: "read", ScopeType: "tenant"},
	"PUT /admin/v1/mcp-redline-settings": {Resource: "mcp_policies", Action: "write", ScopeType: "tenant"},
	// “只允许勾选的工具”模板：挂在 mcp_servers 资源下（与 sync/admission 同口径）
	"GET /admin/v1/mcp-servers/{id}/allowlist-template":    {Resource: "mcp_servers", Action: "read", ScopeType: "tenant"},
	"POST /admin/v1/mcp-servers/{id}/allowlist-template":   {Resource: "mcp_servers", Action: "write", ScopeType: "tenant"},
	"DELETE /admin/v1/mcp-servers/{id}/allowlist-template": {Resource: "mcp_servers", Action: "write", ScopeType: "tenant"},
	// MCP 调用审计全量导出：与 /audit/export 同为 security_events:export（导出权限单独授予）
	"GET /admin/v1/mcp-audit/export":                      {Resource: "security_events", Action: "export", ScopeType: "tenant"},
	"GET /admin/v1/skills/assets":                         {Resource: "skill_assets", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/skills/assets/{id}/versions":           {Resource: "skill_assets", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/skills/invocations":                    {Resource: "skill_assets", Action: "read", ScopeType: "tenant"},
	"POST /admin/v1/skills/scan":                          {Resource: "skill_assets", Action: "write", ScopeType: "tenant"},
	"POST /admin/v1/skills/versions/{id}/admission":       {Resource: "skill_assets", Action: "write", ScopeType: "tenant"},
	"POST /admin/v1/internal/security/skills/definitions": {Resource: "skill_assets", Action: "write", ScopeType: "tenant"},
	"GET /admin/v1/internal/security/skills/admission":    {Resource: "skill_assets", Action: "read", ScopeType: "tenant"},
	"POST /admin/v1/internal/security/skills/invocations": {Resource: "skill_assets", Action: "write", ScopeType: "tenant"},
	"POST /admin/v1/internal/security/skills/results":     {Resource: "skill_assets", Action: "write", ScopeType: "tenant"},
	"GET /admin/v1/provider-price-snapshots":              {Resource: "pricing", Action: "read", ScopeType: "tenant"},
	"POST /admin/v1/anomalies/{id}/ack":                   {Resource: "security_events", Action: "write", ScopeType: "tenant"},
	"GET /admin/v1/forecast/jobs/{id}":                    {Resource: "forecast_jobs", Action: "read", ScopeType: "tenant"},
	"PUT /admin/v1/routing-policies":                      {Resource: "routing_policies", Action: "write", ScopeType: "tenant"},
	"POST /admin/v1/routing-policies/test":                {Resource: "routing_policies", Action: "read", ScopeType: "tenant"},

	// Roles (new)
	"GET /admin/v1/roles":                    {Resource: "users", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/roles/{name}/permissions": {Resource: "users", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/permissions/resources":    {Resource: "users", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/permissions/actions":      {Resource: "users", Action: "read", ScopeType: "tenant"},

	// 训练语料扫描（规格 5.7）：写操作与下载副本为 write，列表/详情/报告为 read。
	// chunks/{id} 一行供不带 chi 路由上下文的路径归一化使用（分片序号也会被归一成 {id}）。
	"POST /admin/v1/security/corpus-scans":                 {Resource: "security_events", Action: "write", ScopeType: "tenant"},
	"GET /admin/v1/security/corpus-scans":                  {Resource: "security_events", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/security/corpus-scans/{id}":             {Resource: "security_events", Action: "read", ScopeType: "tenant"},
	"DELETE /admin/v1/security/corpus-scans/{id}":          {Resource: "security_events", Action: "write", ScopeType: "tenant"},
	"PUT /admin/v1/security/corpus-scans/{id}/chunks/{n}":  {Resource: "security_events", Action: "write", ScopeType: "tenant"},
	"PUT /admin/v1/security/corpus-scans/{id}/chunks/{id}": {Resource: "security_events", Action: "write", ScopeType: "tenant"},
	"POST /admin/v1/security/corpus-scans/{id}/start":      {Resource: "security_events", Action: "write", ScopeType: "tenant"},
	"POST /admin/v1/security/corpus-scans/{id}/cancel":     {Resource: "security_events", Action: "write", ScopeType: "tenant"},
	"GET /admin/v1/security/corpus-scans/{id}/report":      {Resource: "security_events", Action: "read", ScopeType: "tenant"},
	"GET /admin/v1/security/corpus-scans/{id}/masked":      {Resource: "security_events", Action: "write", ScopeType: "tenant"},
}

// ResolvedPermission is the result of resolving a request's required permission
type ResolvedPermission struct {
	Resource             string
	Action               string
	ScopeType            string
	ScopeID              string
	RequirePlatformAdmin bool // true for unregistered paths
}

// Resolve extracts the required permission from an HTTP request
func Resolve(r *http.Request) ResolvedPermission {
	method := r.Method
	path := r.URL.Path

	// Try exact path first (no params)
	key := method + " " + path
	if rp, ok := routeTable[key]; ok {
		return buildResolved(rp, r)
	}

	// Try chi route pattern
	rctx := chi.RouteContext(r.Context())
	if rctx != nil && rctx.RoutePattern() != "" {
		pattern := rctx.RoutePattern()
		key = method + " " + pattern
		if rp, ok := routeTable[key]; ok {
			return buildResolved(rp, r)
		}
	}

	// Template matching: replace URL segments that look like IDs
	normalized := normalizePathToTemplate(path)
	if normalized != path {
		key = method + " " + normalized
		if rp, ok := routeTable[key]; ok {
			return buildResolved(rp, r)
		}
	}

	// Unregistered path: require platform_admin
	return ResolvedPermission{
		Resource:             "users",
		Action:               "read",
		ScopeType:            "tenant",
		RequirePlatformAdmin: true,
	}
}

func buildResolved(rp RoutePermission, r *http.Request) ResolvedPermission {
	scopeID := ""
	if rp.ScopeIDSource != "" {
		if strings.HasPrefix(rp.ScopeIDSource, "url:") {
			param := strings.TrimPrefix(rp.ScopeIDSource, "url:")
			scopeID = chi.URLParam(r, param)
			if scopeID == "" {
				// Fall back to extracting from path
				scopeID = extractPathSegment(r.URL.Path, param)
			}
		}
	}
	return ResolvedPermission{
		Resource:  rp.Resource,
		Action:    rp.Action,
		ScopeType: rp.ScopeType,
		ScopeID:   scopeID,
	}
}

// normalizePathToTemplate replaces non-keyword path segments with {id} or {name}
// e.g. /admin/v1/users/user_abc123/grants -> /admin/v1/users/{id}/grants
func normalizePathToTemplate(path string) string {
	parts := strings.Split(path, "/")
	for i, part := range parts {
		if part == "" || part == "admin" || part == "v1" {
			continue
		}
		// Known non-id segments
		knownSegments := map[string]bool{
			"credential-hits":    true,
			"retention-status":   true,
			"dlp-status":         true,
			"audit-events":       true,
			"agent-credentials":  true,
			"agent-policies":     true,
			"enforcement-status": true,
			"upstreams":          true,
			"rotate":             true,
			"users":              true, "teams": true, "projects": true, "keys": true,
			"providers": true, "models": true, "policies": true, "audit-chain": true,
			"security": true, "events": true, "policy-assets": true, "savings": true, "fx": true,
			"forecast": true, "jobs": true, "routing-policies": true, "routing-decisions": true, "notify": true,
			"channels": true, "alerts": true, "budgets": true, "roles": true,
			"agent-operation-protection": true, "agent-operation-events": true, "block-records": true,
			"principals": true, "intent-tasks": true, "delegation-tree": true, "delegations": true, "calls": true,
			"permissions": true, "resources": true, "actions": true,
			"model": true, "quota": true, "stats": true, "verify": true,
			"export": true, "summary": true, "project-breakdown": true,
			"members": true, "grants": true, "status": true, "detail": true,
			"login-history": true, "reset-password": true, "change-password": true,
			"sync": true, "pricing": true, "routing": true, "proxy-config": true,
			"department": true, "automatic": true,
			"credentials": true, "history": true, "revoke": true, "reveal": true, "restore": true, "deleted": true, "pause": true,
			"resume": true, "me": true, "logout": true, "login": true,
			"catalog": true, "tenant": true, "tenants": true, "settings": true,
			"org-labels": true, "rule-sets": true, "rules": true, "publish": true,
			"policy-suggestions": true, "approve": true, "reject": true,
			"eval-integration": true,
			"detectors":        true, "batch-update": true, "init": true, "audit": true,
			"integration": true, "capabilities": true,
			"requests": true, "records": true, "dispositions": true, "content": true, "usage": true,
			"by-project": true, "cost-coverage": true, "by-model": true,
			"by-user": true, "by-key": true, "by-provider": true,
			"recommendations": true, "agent-sessions": true, "distribution": true,
			"by-type": true, "agents": true, "tools": true, "high-risk": true,
			"session": true, "trend": true, "config": true, "batch": true,
			"proxy": true, "whitelist": true, "reverse-proxy": true, "routes": true,
			"ca": true, "generate": true, "certificate": true, "download": true,
			"list": true, "system": true, "version": true, "upgrade": true,
			"check": true, "upload": true, "execute": true, "rollback": true,
			"ruleset": true, "budget": true, "effective": true, "personal-budget": true,
			"snapshot": true, "unpause": true, "pause-log": true, "prices": true,
			"import": true, "sync-status": true, "current": true, "inbox": true,
			"read": true, "notify-channels": true, "anomalies": true, "ack": true,
			"billing": true, "customers": true, "customer-groups": true, "group": true,
			"wallets": true, "credit": true, "adjustments": true, "ledger": true,
			"exceptions": true, "redemptions": true, "tariffs": true, "newapi-ratio": true,
			"cache-true-up": true,
			"license":       true, "trial": true,
			"test": true, "mcp-servers": true, "mcp-tools": true, "mcp-policies": true, "agentguard": true,
			"internal": true, "skills": true, "assets": true, "scan": true,
			"identity": true, "department-mappings": true, "dept-mappings": true,
			"versions": true, "admission": true, "definitions": true, "invocations": true,
			"results":      true,
			"unlock-login": true, "reset-totp": true, "login-security": true, "portal-login-baseline": true,
			"agent": true, "endpoints": true, "unified-assets": true, "ownership": true, "sources": true, "merge": true,
			"approval-rules": true, "deactivate": true,
			"clusters": true, "namespaces": true, "kubernetes": true, "coverage": true,
			"enrollment-tokens": true, "rotate-token": true, "policy-bundles": true, "mode": true, "sessions": true,
			"approvals": true, "approval-exceptions": true, "approval-requests": true, "approval-claims": true,
			"resolve":     true,
			"diagnostics": true, "bundle": true, "messages": true, "badge": true,
			"corpus-scans": true, "chunks": true, "masked": true, "report": true, "start": true, "cancel": true,
		}
		if !knownSegments[part] {
			// looks like an ID — use {id} unless specific context
			if i > 0 && parts[i-1] == "clusters" {
				parts[i] = "{cluster_id}"
			} else if i > 0 && parts[i-1] == "namespaces" {
				parts[i] = "{registration_id}"
			} else if i > 0 && parts[i-1] == "roles" {
				parts[i] = "{name}"
			} else if i > 0 && parts[i-1] == "grants" {
				parts[i] = "{grant_id}"
			} else if i > 1 && parts[i-1] == "projects" && parts[i-2] == "{id}" {
				parts[i] = "{projectId}"
			} else {
				parts[i] = "{id}"
			}
		}
	}
	return strings.Join(parts, "/")
}

// extractPathSegment tries to extract a named path param from URL by position
// e.g. extractPathSegment("/admin/v1/teams/team_abc/members", "id") => "team_abc"
func extractPathSegment(path, paramName string) string {
	_ = paramName // We use positional heuristics
	parts := strings.Split(path, "/")
	// For most routes, the ID is at index 4 (after "admin/v1/resource")
	if len(parts) >= 5 {
		return parts[4]
	}
	return ""
}
