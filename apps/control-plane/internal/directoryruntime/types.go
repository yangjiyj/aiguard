package directoryruntime

import (
	"errors"
	"fmt"
	"strings"
)

const (
	ProviderName       = "jjdguard-directory"
	ProviderID         = "ldap"
	ProviderType       = "org.keycloak.storage.UserStorageProvider"
	ADBinaryMapperName = "jjdguard-objectguid-binary"
	LDAPMapperType     = "org.keycloak.storage.ldap.mappers.LDAPStorageMapper"
)

var ErrInvalidDirectoryConfig = errors.New("invalid directory runtime configuration")

type DirectoryKind string

const (
	KindActiveDirectory DirectoryKind = "ad"
	KindLDAP            DirectoryKind = "ldap"
)

type DirectoryConfig struct {
	Kind          DirectoryKind
	ConnectionURL string
	BindDN        string
	BindPassword  string
	UsersDN       string
}

func (config DirectoryConfig) String() string {
	return fmt.Sprintf("directoryruntime.DirectoryConfig{Kind:%q Config:[redacted]}", config.Kind)
}

func (config DirectoryConfig) GoString() string {
	return config.String()
}

type ComponentRepresentation struct {
	ID           string              `json:"id,omitempty"`
	Name         string              `json:"name"`
	ProviderID   string              `json:"providerId"`
	ProviderType string              `json:"providerType"`
	ParentID     string              `json:"parentId,omitempty"`
	Config       map[string][]string `json:"config"`
}

func (component ComponentRepresentation) String() string {
	return fmt.Sprintf("directoryruntime.ComponentRepresentation{ID:%q Name:%q ProviderID:%q ProviderType:%q ParentID:%q Config:[redacted]}",
		component.ID, component.Name, component.ProviderID, component.ProviderType, component.ParentID)
}

func (component ComponentRepresentation) GoString() string {
	return component.String()
}

func DesiredProvider(config DirectoryConfig) (ComponentRepresentation, error) {
	if err := validateDirectoryConfig(config); err != nil {
		return ComponentRepresentation{}, err
	}
	vendor := "other"
	uuidAttribute := "entryUUID"
	usernameAttribute := "uid"
	userObjectClasses := "inetOrgPerson,organizationalPerson"
	rdnAttribute := "uid"
	if config.Kind == KindActiveDirectory {
		vendor = "ad"
		uuidAttribute = "objectGUID"
		usernameAttribute = "sAMAccountName"
		userObjectClasses = "person,organizationalPerson,user"
		rdnAttribute = "cn"
	}
	provider := ComponentRepresentation{
		Name:         ProviderName,
		ProviderID:   ProviderID,
		ProviderType: ProviderType,
		Config: map[string][]string{
			"connectionUrl":         {strings.TrimSpace(config.ConnectionURL)},
			"bindDn":                {strings.TrimSpace(config.BindDN)},
			"bindCredential":        {config.BindPassword},
			"usersDn":               {strings.TrimSpace(config.UsersDN)},
			"vendor":                {vendor},
			"uuidLDAPAttribute":     {uuidAttribute},
			"usernameLDAPAttribute": {usernameAttribute},
			"userObjectClasses":     {userObjectClasses},
			"rdnLDAPAttribute":      {rdnAttribute},
			"editMode":              {"READ_ONLY"},
			"importEnabled":         {"true"},
			"syncRegistrations":     {"false"},
			"enabled":               {"true"},
		},
	}
	// W9 9.4：ldap:// 目录必须让 Keycloak 先 StartTLS 再 bind，否则 bind 凭据明文上网。
	if usesStartTLS(config.ConnectionURL) {
		provider.Config["startTls"] = []string{"true"}
	}
	return provider, nil
}

func DesiredADBinaryMapper(parentID string) ComponentRepresentation {
	return ComponentRepresentation{
		Name:         ADBinaryMapperName,
		ProviderID:   "user-attribute-ldap-mapper",
		ProviderType: LDAPMapperType,
		ParentID:     parentID,
		Config: map[string][]string{
			"ldap.attribute":              {"objectGUID"},
			"user.model.attribute":        {"jjdguardObjectGUID"},
			"read.only":                   {"true"},
			"always.read.value.from.ldap": {"true"},
			"is.mandatory.in.ldap":        {"true"},
			"is.binary.attribute":         {"true"},
		},
	}
}

func DesiredStandardLDAPMappers(parentID string, kind DirectoryKind) []ComponentRepresentation {
	usernameAttribute := "uid"
	if kind == KindActiveDirectory {
		usernameAttribute = "sAMAccountName"
	}
	type mapperSpec struct {
		name, ldapAttribute, userAttribute, mandatory, alwaysRead string
	}
	specs := []mapperSpec{
		{name: "username", ldapAttribute: usernameAttribute, userAttribute: "username", mandatory: "true", alwaysRead: "false"},
		{name: "first name", ldapAttribute: "givenName", userAttribute: "firstName", mandatory: "false", alwaysRead: "true"},
		{name: "last name", ldapAttribute: "sn", userAttribute: "lastName", mandatory: "false", alwaysRead: "true"},
		{name: "email", ldapAttribute: "mail", userAttribute: "email", mandatory: "false", alwaysRead: "false"},
	}
	mappers := make([]ComponentRepresentation, 0, len(specs))
	for _, spec := range specs {
		mappers = append(mappers, ComponentRepresentation{
			Name: spec.name, ProviderID: "user-attribute-ldap-mapper",
			ProviderType: LDAPMapperType, ParentID: parentID,
			Config: map[string][]string{
				"ldap.attribute":              {spec.ldapAttribute},
				"user.model.attribute":        {spec.userAttribute},
				"read.only":                   {"true"},
				"always.read.value.from.ldap": {spec.alwaysRead},
				"is.mandatory.in.ldap":        {spec.mandatory},
			},
		})
	}
	return mappers
}

// usesStartTLS：ldap:// 地址（与 directoryldap.TransportFor 同一口径）；ldaps:// 为隐式 TLS。
func usesStartTLS(connectionURL string) bool {
	return strings.HasPrefix(strings.TrimSpace(connectionURL), "ldap://")
}

func validateDirectoryConfig(config DirectoryConfig) error {
	switch config.Kind {
	case KindActiveDirectory, KindLDAP:
	default:
		return ErrInvalidDirectoryConfig
	}
	if strings.TrimSpace(config.ConnectionURL) == "" ||
		strings.TrimSpace(config.BindDN) == "" ||
		config.BindPassword == "" ||
		strings.TrimSpace(config.UsersDN) == "" {
		return ErrInvalidDirectoryConfig
	}
	return nil
}
