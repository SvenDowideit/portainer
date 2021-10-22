package portainer

import (
	"io"
)

type (
	// DataStore defines the interface to manage the data
	DataStore interface {
		Open() error
		Init() error
		Close() error
		IsNew() bool
		MigrateData(force bool) error
		Rollback(force bool) error
		CheckCurrentEdition() error
		BackupTo(w io.Writer) error

		CustomTemplate() CustomTemplateService
		EdgeGroup() EdgeGroupService
		EdgeJob() EdgeJobService
		EdgeStack() EdgeStackService
		Endpoint() EndpointService
		EndpointGroup() EndpointGroupService
		EndpointRelation() EndpointRelationService
		HelmUserRepository() HelmUserRepositoryService
		Registry() RegistryService
		ResourceControl() ResourceControlService
		Role() RoleService
		Settings() SettingsService
		SSLSettings() SSLSettingsService
		Stack() StackService
		Tag() TagService
		TeamMembership() TeamMembershipService
		Team() TeamService
		TunnelServer() TunnelServerService
		User() UserService
		Version() VersionService
		Webhook() WebhookService
	}

	// CustomTemplateService represents a service to manage custom templates
	CustomTemplateService interface {
		GetNextIdentifier() int
		CustomTemplates() ([]CustomTemplate, error)
		CustomTemplate(ID CustomTemplateID) (*CustomTemplate, error)
		CreateCustomTemplate(customTemplate *CustomTemplate) error
		UpdateCustomTemplate(ID CustomTemplateID, customTemplate *CustomTemplate) error
		DeleteCustomTemplate(ID CustomTemplateID) error
	}

	// EdgeGroupService represents a service to manage Edge groups
	EdgeGroupService interface {
		EdgeGroups() ([]EdgeGroup, error)
		EdgeGroup(ID EdgeGroupID) (*EdgeGroup, error)
		CreateEdgeGroup(group *EdgeGroup) error
		UpdateEdgeGroup(ID EdgeGroupID, group *EdgeGroup) error
		DeleteEdgeGroup(ID EdgeGroupID) error
	}

	// EdgeJobService represents a service to manage Edge jobs
	EdgeJobService interface {
		EdgeJobs() ([]EdgeJob, error)
		EdgeJob(ID EdgeJobID) (*EdgeJob, error)
		CreateEdgeJob(edgeJob *EdgeJob) error
		UpdateEdgeJob(ID EdgeJobID, edgeJob *EdgeJob) error
		DeleteEdgeJob(ID EdgeJobID) error
		GetNextIdentifier() int
	}

	// EdgeStackService represents a service to manage Edge stacks
	EdgeStackService interface {
		EdgeStacks() ([]EdgeStack, error)
		EdgeStack(ID EdgeStackID) (*EdgeStack, error)
		CreateEdgeStack(edgeStack *EdgeStack) error
		UpdateEdgeStack(ID EdgeStackID, edgeStack *EdgeStack) error
		DeleteEdgeStack(ID EdgeStackID) error
		GetNextIdentifier() int
	}

	// EndpointService represents a service for managing environment(endpoint) data
	EndpointService interface {
		Endpoint(ID EndpointID) (*Endpoint, error)
		Endpoints() ([]Endpoint, error)
		CreateEndpoint(endpoint *Endpoint) error
		UpdateEndpoint(ID EndpointID, endpoint *Endpoint) error
		DeleteEndpoint(ID EndpointID) error
		Synchronize(toCreate, toUpdate, toDelete []*Endpoint) error
		GetNextIdentifier() int
	}

	// EndpointGroupService represents a service for managing environment(endpoint) group data
	EndpointGroupService interface {
		EndpointGroup(ID EndpointGroupID) (*EndpointGroup, error)
		EndpointGroups() ([]EndpointGroup, error)
		CreateEndpointGroup(group *EndpointGroup) error
		UpdateEndpointGroup(ID EndpointGroupID, group *EndpointGroup) error
		DeleteEndpointGroup(ID EndpointGroupID) error
	}

	// EndpointRelationService represents a service for managing environment(endpoint) relations data
	EndpointRelationService interface {
		EndpointRelation(EndpointID EndpointID) (*EndpointRelation, error)
		CreateEndpointRelation(endpointRelation *EndpointRelation) error
		UpdateEndpointRelation(EndpointID EndpointID, endpointRelation *EndpointRelation) error
		DeleteEndpointRelation(EndpointID EndpointID) error
	}

	// HelmUserRepositoryService represents a service to manage HelmUserRepositories
	HelmUserRepositoryService interface {
		HelmUserRepositoryByUserID(userID UserID) ([]HelmUserRepository, error)
		CreateHelmUserRepository(record *HelmUserRepository) error
	}
	

	// RegistryService represents a service for managing registry data
	RegistryService interface {
		Registry(ID RegistryID) (*Registry, error)
		Registries() ([]Registry, error)
		CreateRegistry(registry *Registry) error
		UpdateRegistry(ID RegistryID, registry *Registry) error
		DeleteRegistry(ID RegistryID) error
	}

	// ResourceControlService represents a service for managing resource control data
	ResourceControlService interface {
		ResourceControl(ID ResourceControlID) (*ResourceControl, error)
		ResourceControlByResourceIDAndType(resourceID string, resourceType ResourceControlType) (*ResourceControl, error)
		ResourceControls() ([]ResourceControl, error)
		CreateResourceControl(rc *ResourceControl) error
		UpdateResourceControl(ID ResourceControlID, resourceControl *ResourceControl) error
		DeleteResourceControl(ID ResourceControlID) error
	}

		// RoleService represents a service for managing user roles
		RoleService interface {
			Role(ID RoleID) (*Role, error)
			Roles() ([]Role, error)
			CreateRole(role *Role) error
			UpdateRole(ID RoleID, role *Role) error
		}
	
		// SettingsService represents a service for managing application settings
		SettingsService interface {
			Settings() (*Settings, error)
			UpdateSettings(settings *Settings) error
		}

	// SSLSettingsService represents a service for managing application settings
	SSLSettingsService interface {
		Settings() (*SSLSettings, error)
		UpdateSettings(settings *SSLSettings) error
	}

	// StackService represents a service for managing stack data
	StackService interface {
		Stack(ID StackID) (*Stack, error)
		StackByName(name string) (*Stack, error)
		Stacks() ([]Stack, error)
		CreateStack(stack *Stack) error
		UpdateStack(ID StackID, stack *Stack) error
		DeleteStack(ID StackID) error
		GetNextIdentifier() int
		StackByWebhookID(ID string) (*Stack, error)
		RefreshableStacks() ([]Stack, error)
	}
	// TagService represents a service for managing tag data
	TagService interface {
		Tags() ([]Tag, error)
		Tag(ID TagID) (*Tag, error)
		CreateTag(tag *Tag) error
		UpdateTag(ID TagID, tag *Tag) error
		DeleteTag(ID TagID) error
	}

	// TeamService represents a service for managing user data
	TeamService interface {
		Team(ID TeamID) (*Team, error)
		TeamByName(name string) (*Team, error)
		Teams() ([]Team, error)
		CreateTeam(team *Team) error
		UpdateTeam(ID TeamID, team *Team) error
		DeleteTeam(ID TeamID) error
	}

	// TeamMembershipService represents a service for managing team membership data
	TeamMembershipService interface {
		TeamMembership(ID TeamMembershipID) (*TeamMembership, error)
		TeamMemberships() ([]TeamMembership, error)
		TeamMembershipsByUserID(userID UserID) ([]TeamMembership, error)
		TeamMembershipsByTeamID(teamID TeamID) ([]TeamMembership, error)
		CreateTeamMembership(membership *TeamMembership) error
		UpdateTeamMembership(ID TeamMembershipID, membership *TeamMembership) error
		DeleteTeamMembership(ID TeamMembershipID) error
		DeleteTeamMembershipByUserID(userID UserID) error
		DeleteTeamMembershipByTeamID(teamID TeamID) error
	}

	// TunnelServerService represents a service for managing data associated to the tunnel server
	TunnelServerService interface {
		Info() (*TunnelServerInfo, error)
		UpdateInfo(info *TunnelServerInfo) error
	}

	// UserService represents a service for managing user data
	UserService interface {
		User(ID UserID) (*User, error)
		UserByUsername(username string) (*User, error)
		Users() ([]User, error)
		UsersByRole(role UserRole) ([]User, error)
		CreateUser(user *User) error
		UpdateUser(ID UserID, user *User) error
		DeleteUser(ID UserID) error
	}

	// VersionService represents a service for managing version data
	VersionService interface {
		DBVersion() (int, error)
		Edition() (SoftwareEdition, error)
		InstanceID() (string, error)
		StoreDBVersion(version int) error
		StoreInstanceID(ID string) error
	}

	// WebhookService represents a service for managing webhook data.
	WebhookService interface {
		Webhooks() ([]Webhook, error)
		Webhook(ID WebhookID) (*Webhook, error)
		CreateWebhook(portainer *Webhook) error
		WebhookByResourceID(resourceID string) (*Webhook, error)
		WebhookByToken(token string) (*Webhook, error)
		DeleteWebhook(serviceID WebhookID) error
	}

)