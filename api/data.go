package portainer

import (
	"time"

	gittypes "github.com/portainer/portainer/api/git/types"

)

type (
	// CustomTemplate represents a custom template
	CustomTemplate struct {
		// CustomTemplate Identifier
		ID CustomTemplateID `json:"Id" example:"1"`
		// Title of the template
		Title string `json:"Title" example:"Nginx"`
		// Description of the template
		Description string `json:"Description" example:"High performance web server"`
		// Path on disk to the repository hosting the Stack file
		ProjectPath string `json:"ProjectPath" example:"/data/custom_template/3"`
		// Path to the Stack file
		EntryPoint string `json:"EntryPoint" example:"docker-compose.yml"`
		// User identifier who created this template
		CreatedByUserID UserID `json:"CreatedByUserId" example:"3"`
		// A note that will be displayed in the UI. Supports HTML content
		Note string `json:"Note" example:"This is my <b>custom</b> template"`
		// Platform associated to the template.
		// Valid values are: 1 - 'linux', 2 - 'windows'
		Platform CustomTemplatePlatform `json:"Platform" example:"1" enums:"1,2"`
		// URL of the template's logo
		Logo string `json:"Logo" example:"https://cloudinovasi.id/assets/img/logos/nginx.png"`
		// Type of created stack (1 - swarm, 2 - compose)
		Type            StackType        `json:"Type" example:"1"`
		ResourceControl *ResourceControl `json:"ResourceControl"`
	}

	// CustomTemplateID represents a custom template identifier
	CustomTemplateID int

	// CustomTemplatePlatform represents a custom template platform
	CustomTemplatePlatform int

	// DockerHub represents all the required information to connect and use the
	// Docker Hub
	DockerHub struct {
		// Is authentication against DockerHub enabled
		Authentication bool `json:"Authentication" example:"true"`
		// Username used to authenticate against the DockerHub
		Username string `json:"Username" example:"user"`
		// Password used to authenticate against the DockerHub
		Password string `json:"Password,omitempty" example:"passwd"`
	}

	// DockerSnapshot represents a snapshot of a specific Docker environment(endpoint) at a specific time
	DockerSnapshot struct {
		Time                    int64             `json:"Time"`
		DockerVersion           string            `json:"DockerVersion"`
		Swarm                   bool              `json:"Swarm"`
		TotalCPU                int               `json:"TotalCPU"`
		TotalMemory             int64             `json:"TotalMemory"`
		RunningContainerCount   int               `json:"RunningContainerCount"`
		StoppedContainerCount   int               `json:"StoppedContainerCount"`
		HealthyContainerCount   int               `json:"HealthyContainerCount"`
		UnhealthyContainerCount int               `json:"UnhealthyContainerCount"`
		VolumeCount             int               `json:"VolumeCount"`
		ImageCount              int               `json:"ImageCount"`
		ServiceCount            int               `json:"ServiceCount"`
		StackCount              int               `json:"StackCount"`
		NodeCount               int               `json:"NodeCount"`
		SnapshotRaw             DockerSnapshotRaw `json:"DockerSnapshotRaw"`
	}

	// DockerSnapshotRaw represents all the information related to a snapshot as returned by the Docker API
	DockerSnapshotRaw struct {
		Containers interface{} `json:"Containers"`
		Volumes    interface{} `json:"Volumes"`
		Networks   interface{} `json:"Networks"`
		Images     interface{} `json:"Images"`
		Info       interface{} `json:"Info"`
		Version    interface{} `json:"Version"`
	}

	// EdgeGroup represents an Edge group
	EdgeGroup struct {
		// EdgeGroup Identifier
		ID           EdgeGroupID  `json:"Id" example:"1"`
		Name         string       `json:"Name"`
		Dynamic      bool         `json:"Dynamic"`
		TagIDs       []TagID      `json:"TagIds"`
		Endpoints    []EndpointID `json:"Endpoints"`
		PartialMatch bool         `json:"PartialMatch"`
	}

	// EdgeGroupID represents an Edge group identifier
	EdgeGroupID int

	// EdgeJob represents a job that can run on Edge environments(endpoints).
	EdgeJob struct {
		// EdgeJob Identifier
		ID             EdgeJobID                          `json:"Id" example:"1"`
		Created        int64                              `json:"Created"`
		CronExpression string                             `json:"CronExpression"`
		Endpoints      map[EndpointID]EdgeJobEndpointMeta `json:"Endpoints"`
		Name           string                             `json:"Name"`
		ScriptPath     string                             `json:"ScriptPath"`
		Recurring      bool                               `json:"Recurring"`
		Version        int                                `json:"Version"`
	}

	// EdgeJobEndpointMeta represents a meta data object for an Edge job and Environment(Endpoint) relation
	EdgeJobEndpointMeta struct {
		LogsStatus  EdgeJobLogsStatus
		CollectLogs bool
	}

	// EdgeJobID represents an Edge job identifier
	EdgeJobID int

	// EdgeJobLogsStatus represent status of logs collection job
	EdgeJobLogsStatus int

	// EdgeSchedule represents a scheduled job that can run on Edge environments(endpoints).
	// Deprecated in favor of EdgeJob
	EdgeSchedule struct {
		// EdgeSchedule Identifier
		ID             ScheduleID   `json:"Id" example:"1"`
		CronExpression string       `json:"CronExpression"`
		Script         string       `json:"Script"`
		Version        int          `json:"Version"`
		Endpoints      []EndpointID `json:"Endpoints"`
	}

	//EdgeStack represents an edge stack
	EdgeStack struct {
		// EdgeStack Identifier
		ID             EdgeStackID                    `json:"Id" example:"1"`
		Name           string                         `json:"Name"`
		Status         map[EndpointID]EdgeStackStatus `json:"Status"`
		CreationDate   int64                          `json:"CreationDate"`
		EdgeGroups     []EdgeGroupID                  `json:"EdgeGroups"`
		ProjectPath    string                         `json:"ProjectPath"`
		EntryPoint     string                         `json:"EntryPoint"`
		Version        int                            `json:"Version"`
		ManifestPath   string
		DeploymentType EdgeStackDeploymentType

		// Deprecated
		Prune bool `json:"Prune"`
	}

	EdgeStackDeploymentType int

	//EdgeStackID represents an edge stack id
	EdgeStackID int

	//EdgeStackStatus represents an edge stack status
	EdgeStackStatus struct {
		Type       EdgeStackStatusType `json:"Type"`
		Error      string              `json:"Error"`
		EndpointID EndpointID          `json:"EndpointID"`
	}

	//EdgeStackStatusType represents an edge stack status type
	EdgeStackStatusType int

	// Environment(Endpoint) represents a Docker environment(endpoint) with all the info required
	// to connect to it
	Endpoint struct {
		// Environment(Endpoint) Identifier
		ID EndpointID `json:"Id" example:"1"`
		// Environment(Endpoint) name
		Name string `json:"Name" example:"my-environment"`
		// Environment(Endpoint) environment(endpoint) type. 1 for a Docker environment(endpoint), 2 for an agent on Docker environment(endpoint) or 3 for an Azure environment(endpoint).
		Type EndpointType `json:"Type" example:"1"`
		// URL or IP address of the Docker host associated to this environment(endpoint)
		URL string `json:"URL" example:"docker.mydomain.tld:2375"`
		// Environment(Endpoint) group identifier
		GroupID EndpointGroupID `json:"GroupId" example:"1"`
		// URL or IP address where exposed containers will be reachable
		PublicURL        string              `json:"PublicURL" example:"docker.mydomain.tld:2375"`
		TLSConfig        TLSConfiguration    `json:"TLSConfig"`
		Extensions       []EndpointExtension `json:"Extensions" example:""`
		AzureCredentials AzureCredentials    `json:"AzureCredentials,omitempty" example:""`
		// List of tag identifiers to which this environment(endpoint) is associated
		TagIDs []TagID `json:"TagIds"`
		// The status of the environment(endpoint) (1 - up, 2 - down)
		Status EndpointStatus `json:"Status" example:"1"`
		// List of snapshots
		Snapshots []DockerSnapshot `json:"Snapshots" example:""`
		// List of user identifiers authorized to connect to this environment(endpoint)
		UserAccessPolicies UserAccessPolicies `json:"UserAccessPolicies"`
		// List of team identifiers authorized to connect to this environment(endpoint)
		TeamAccessPolicies TeamAccessPolicies `json:"TeamAccessPolicies" example:""`
		// The identifier of the edge agent associated with this environment(endpoint)
		EdgeID string `json:"EdgeID,omitempty" example:""`
		// The key which is used to map the agent to Portainer
		EdgeKey string `json:"EdgeKey" example:""`
		// The check in interval for edge agent (in seconds)
		EdgeCheckinInterval int `json:"EdgeCheckinInterval" example:"5"`
		// Associated Kubernetes data
		Kubernetes KubernetesData `json:"Kubernetes" example:""`
		// Maximum version of docker-compose
		ComposeSyntaxMaxVersion string `json:"ComposeSyntaxMaxVersion" example:"3.8"`
		// Environment(Endpoint) specific security settings
		SecuritySettings EndpointSecuritySettings
		// LastCheckInDate mark last check-in date on checkin
		LastCheckInDate int64

		// Deprecated fields
		// Deprecated in DBVersion == 4
		TLS           bool   `json:"TLS,omitempty"`
		TLSCACertPath string `json:"TLSCACert,omitempty"`
		TLSCertPath   string `json:"TLSCert,omitempty"`
		TLSKeyPath    string `json:"TLSKey,omitempty"`

		// Deprecated in DBVersion == 18
		AuthorizedUsers []UserID `json:"AuthorizedUsers"`
		AuthorizedTeams []TeamID `json:"AuthorizedTeams"`

		// Deprecated in DBVersion == 22
		Tags []string `json:"Tags"`
	}

	// EndpointAuthorizations represents the authorizations associated to a set of environments(endpoints)
	EndpointAuthorizations map[EndpointID]Authorizations

	// EndpointExtension represents a deprecated form of Portainer extension
	// TODO: legacy extension management
	EndpointExtension struct {
		Type EndpointExtensionType `json:"Type"`
		URL  string                `json:"URL"`
	}

	// EndpointExtensionType represents the type of an environment(endpoint) extension. Only
	// one extension of each type can be associated to an environment(endpoint)
	EndpointExtensionType int

	// EndpointGroup represents a group of environments(endpoints)
	EndpointGroup struct {
		// Environment(Endpoint) group Identifier
		ID EndpointGroupID `json:"Id" example:"1"`
		// Environment(Endpoint) group name
		Name string `json:"Name" example:"my-environment-group"`
		// Description associated to the environment(endpoint) group
		Description        string             `json:"Description" example:"Environment(Endpoint) group description"`
		UserAccessPolicies UserAccessPolicies `json:"UserAccessPolicies" example:""`
		TeamAccessPolicies TeamAccessPolicies `json:"TeamAccessPolicies" example:""`
		// List of tags associated to this environment(endpoint) group
		TagIDs []TagID `json:"TagIds"`

		// Deprecated fields
		Labels []Pair `json:"Labels"`

		// Deprecated in DBVersion == 18
		AuthorizedUsers []UserID `json:"AuthorizedUsers"`
		AuthorizedTeams []TeamID `json:"AuthorizedTeams"`

		// Deprecated in DBVersion == 22
		Tags []string `json:"Tags"`
	}

	// EndpointGroupID represents an environment(endpoint) group identifier
	EndpointGroupID int

	// EndpointID represents an environment(endpoint) identifier
	EndpointID int

	// EndpointStatus represents the status of an environment(endpoint)
	EndpointStatus int

	// EndpointSyncJob represents a scheduled job that synchronize environments(endpoints) based on an external file
	// Deprecated
	EndpointSyncJob struct{}

	// EndpointSecuritySettings represents settings for an environment(endpoint)
	EndpointSecuritySettings struct {
		// Whether non-administrator should be able to use bind mounts when creating containers
		AllowBindMountsForRegularUsers bool `json:"allowBindMountsForRegularUsers" example:"false"`
		// Whether non-administrator should be able to use privileged mode when creating containers
		AllowPrivilegedModeForRegularUsers bool `json:"allowPrivilegedModeForRegularUsers" example:"false"`
		// Whether non-administrator should be able to browse volumes
		AllowVolumeBrowserForRegularUsers bool `json:"allowVolumeBrowserForRegularUsers" example:"true"`
		// Whether non-administrator should be able to use the host pid
		AllowHostNamespaceForRegularUsers bool `json:"allowHostNamespaceForRegularUsers" example:"true"`
		// Whether non-administrator should be able to use device mapping
		AllowDeviceMappingForRegularUsers bool `json:"allowDeviceMappingForRegularUsers" example:"true"`
		// Whether non-administrator should be able to manage stacks
		AllowStackManagementForRegularUsers bool `json:"allowStackManagementForRegularUsers" example:"true"`
		// Whether non-administrator should be able to use container capabilities
		AllowContainerCapabilitiesForRegularUsers bool `json:"allowContainerCapabilitiesForRegularUsers" example:"true"`
		// Whether non-administrator should be able to use sysctl settings
		AllowSysctlSettingForRegularUsers bool `json:"allowSysctlSettingForRegularUsers" example:"true"`
		// Whether host management features are enabled
		EnableHostManagementFeatures bool `json:"enableHostManagementFeatures" example:"true"`
	}

	// EndpointType represents the type of an environment(endpoint)
	EndpointType int

	// EndpointRelation represents a environment(endpoint) relation object
	EndpointRelation struct {
		EndpointID EndpointID
		EdgeStacks map[EdgeStackID]bool
	}

	// Extension represents a deprecated Portainer extension
	Extension struct {
		// Extension Identifier
		ID               ExtensionID        `json:"Id" example:"1"`
		Enabled          bool               `json:"Enabled"`
		Name             string             `json:"Name,omitempty"`
		ShortDescription string             `json:"ShortDescription,omitempty"`
		Description      string             `json:"Description,omitempty"`
		DescriptionURL   string             `json:"DescriptionURL,omitempty"`
		Price            string             `json:"Price,omitempty"`
		PriceDescription string             `json:"PriceDescription,omitempty"`
		Deal             bool               `json:"Deal,omitempty"`
		Available        bool               `json:"Available,omitempty"`
		License          LicenseInformation `json:"License,omitempty"`
		Version          string             `json:"Version"`
		UpdateAvailable  bool               `json:"UpdateAvailable"`
		ShopURL          string             `json:"ShopURL,omitempty"`
		Images           []string           `json:"Images,omitempty"`
		Logo             string             `json:"Logo,omitempty"`
	}

	// ExtensionID represents a extension identifier
	ExtensionID int

	// GitlabRegistryData represents data required for gitlab registry to work
	GitlabRegistryData struct {
		ProjectID   int    `json:"ProjectId"`
		InstanceURL string `json:"InstanceURL"`
		ProjectPath string `json:"ProjectPath"`
	}

	HelmUserRepositoryID int

	// HelmUserRepositories stores a Helm repository URL for the given user
	HelmUserRepository struct {
		// Membership Identifier
		ID HelmUserRepositoryID `json:"Id" example:"1"`
		// User identifier
		UserID UserID `json:"UserId" example:"1"`
		// Helm repository URL
		URL string `json:"URL" example:"https://charts.bitnami.com/bitnami"`
	}

	// QuayRegistryData represents data required for Quay registry to work
	QuayRegistryData struct {
		UseOrganisation  bool   `json:"UseOrganisation"`
		OrganisationName string `json:"OrganisationName"`
	}

	// JobType represents a job type
	JobType int

	K8sNodeLimits struct {
		CPU    int64 `json:"CPU"`
		Memory int64 `json:"Memory"`
	}

	K8sNodesLimits map[string]*K8sNodeLimits

	K8sNamespaceAccessPolicy struct {
		UserAccessPolicies UserAccessPolicies `json:"UserAccessPolicies"`
		TeamAccessPolicies TeamAccessPolicies `json:"TeamAccessPolicies"`
	}

	// KubernetesData contains all the Kubernetes related environment(endpoint) information
	KubernetesData struct {
		Snapshots     []KubernetesSnapshot    `json:"Snapshots"`
		Configuration KubernetesConfiguration `json:"Configuration"`
	}

	// KubernetesSnapshot represents a snapshot of a specific Kubernetes environment(endpoint) at a specific time
	KubernetesSnapshot struct {
		Time              int64  `json:"Time"`
		KubernetesVersion string `json:"KubernetesVersion"`
		NodeCount         int    `json:"NodeCount"`
		TotalCPU          int64  `json:"TotalCPU"`
		TotalMemory       int64  `json:"TotalMemory"`
	}

	// KubernetesConfiguration represents the configuration of a Kubernetes environment(endpoint)
	KubernetesConfiguration struct {
		UseLoadBalancer          bool                           `json:"UseLoadBalancer"`
		UseServerMetrics         bool                           `json:"UseServerMetrics"`
		StorageClasses           []KubernetesStorageClassConfig `json:"StorageClasses"`
		IngressClasses           []KubernetesIngressClassConfig `json:"IngressClasses"`
		RestrictDefaultNamespace bool                           `json:"RestrictDefaultNamespace"`
	}

	// KubernetesStorageClassConfig represents a Kubernetes Storage Class configuration
	KubernetesStorageClassConfig struct {
		Name                 string   `json:"Name"`
		AccessModes          []string `json:"AccessModes"`
		Provisioner          string   `json:"Provisioner"`
		AllowVolumeExpansion bool     `json:"AllowVolumeExpansion"`
	}

	// KubernetesIngressClassConfig represents a Kubernetes Ingress Class configuration
	KubernetesIngressClassConfig struct {
		Name string `json:"Name"`
		Type string `json:"Type"`
	}

	// KubernetesShellPod represents a Kubectl Shell details to facilitate pod exec functionality
	KubernetesShellPod struct {
		Namespace        string
		PodName          string
		ContainerName    string
		ShellExecCommand string
	}

	// LDAPGroupSearchSettings represents settings used to search for groups in a LDAP server
	LDAPGroupSearchSettings struct {
		// The distinguished name of the element from which the LDAP server will search for groups
		GroupBaseDN string `json:"GroupBaseDN" example:"dc=ldap,dc=domain,dc=tld"`
		// The LDAP search filter used to select group elements, optional
		GroupFilter string `json:"GroupFilter" example:"(objectClass=account"`
		// LDAP attribute which denotes the group membership
		GroupAttribute string `json:"GroupAttribute" example:"member"`
	}

	// LDAPSearchSettings represents settings used to search for users in a LDAP server
	LDAPSearchSettings struct {
		// The distinguished name of the element from which the LDAP server will search for users
		BaseDN string `json:"BaseDN" example:"dc=ldap,dc=domain,dc=tld"`
		// Optional LDAP search filter used to select user elements
		Filter string `json:"Filter" example:"(objectClass=account)"`
		// LDAP attribute which denotes the username
		UserNameAttribute string `json:"UserNameAttribute" example:"uid"`
	}

	// LDAPSettings represents the settings used to connect to a LDAP server
	LDAPSettings struct {
		// Enable this option if the server is configured for Anonymous access. When enabled, ReaderDN and Password will not be used
		AnonymousMode bool `json:"AnonymousMode" example:"true"`
		// Account that will be used to search for users
		ReaderDN string `json:"ReaderDN" example:"cn=readonly-account,dc=ldap,dc=domain,dc=tld"`
		// Password of the account that will be used to search users
		Password string `json:"Password,omitempty" example:"readonly-password"`
		// URL or IP address of the LDAP server
		URL       string           `json:"URL" example:"myldap.domain.tld:389"`
		TLSConfig TLSConfiguration `json:"TLSConfig"`
		// Whether LDAP connection should use StartTLS
		StartTLS            bool                      `json:"StartTLS" example:"true"`
		SearchSettings      []LDAPSearchSettings      `json:"SearchSettings"`
		GroupSearchSettings []LDAPGroupSearchSettings `json:"GroupSearchSettings"`
		// Automatically provision users and assign them to matching LDAP group names
		AutoCreateUsers bool `json:"AutoCreateUsers" example:"true"`
	}

	// LDAPUser represents a LDAP user
	LDAPUser struct {
		Name   string
		Groups []string
	}

	// LicenseInformation represents information about an extension license
	LicenseInformation struct {
		LicenseKey string `json:"LicenseKey,omitempty"`
		Company    string `json:"Company,omitempty"`
		Expiration string `json:"Expiration,omitempty"`
		Valid      bool   `json:"Valid,omitempty"`
	}

	// MembershipRole represents the role of a user within a team
	MembershipRole int

	// OAuthSettings represents the settings used to authorize with an authorization server
	OAuthSettings struct {
		ClientID             string `json:"ClientID"`
		ClientSecret         string `json:"ClientSecret,omitempty"`
		AccessTokenURI       string `json:"AccessTokenURI"`
		AuthorizationURI     string `json:"AuthorizationURI"`
		ResourceURI          string `json:"ResourceURI"`
		RedirectURI          string `json:"RedirectURI"`
		UserIdentifier       string `json:"UserIdentifier"`
		Scopes               string `json:"Scopes"`
		OAuthAutoCreateUsers bool   `json:"OAuthAutoCreateUsers"`
		DefaultTeamID        TeamID `json:"DefaultTeamID"`
		SSO                  bool   `json:"SSO"`
		LogoutURI            string `json:"LogoutURI"`
	}

	// Pair defines a key/value string pair
	Pair struct {
		Name  string `json:"name" example:"name"`
		Value string `json:"value" example:"value"`
	}

	// Registry represents a Docker registry with all the info required
	// to connect to it
	Registry struct {
		// Registry Identifier
		ID RegistryID `json:"Id" example:"1"`
		// Registry Type (1 - Quay, 2 - Azure, 3 - Custom, 4 - Gitlab, 5 - ProGet, 6 - DockerHub)
		Type RegistryType `json:"Type" enums:"1,2,3,4,5,6"`
		// Registry Name
		Name string `json:"Name" example:"my-registry"`
		// URL or IP address of the Docker registry
		URL string `json:"URL" example:"registry.mydomain.tld:2375"`
		// Base URL, introduced for ProGet registry
		BaseURL string `json:"BaseURL" example:"registry.mydomain.tld:2375"`
		// Is authentication against this registry enabled
		Authentication bool `json:"Authentication" example:"true"`
		// Username used to authenticate against this registry
		Username string `json:"Username" example:"registry user"`
		// Password used to authenticate against this registry
		Password                string                           `json:"Password,omitempty" example:"registry_password"`
		ManagementConfiguration *RegistryManagementConfiguration `json:"ManagementConfiguration"`
		Gitlab                  GitlabRegistryData               `json:"Gitlab"`
		Quay                    QuayRegistryData                 `json:"Quay"`
		RegistryAccesses        RegistryAccesses                 `json:"RegistryAccesses"`

		// Deprecated fields
		// Deprecated in DBVersion == 31
		UserAccessPolicies UserAccessPolicies `json:"UserAccessPolicies"`
		// Deprecated in DBVersion == 31
		TeamAccessPolicies TeamAccessPolicies `json:"TeamAccessPolicies"`

		// Deprecated in DBVersion == 18
		AuthorizedUsers []UserID `json:"AuthorizedUsers"`
		// Deprecated in DBVersion == 18
		AuthorizedTeams []TeamID `json:"AuthorizedTeams"`
	}

	RegistryAccesses map[EndpointID]RegistryAccessPolicies

	RegistryAccessPolicies struct {
		UserAccessPolicies UserAccessPolicies `json:"UserAccessPolicies"`
		TeamAccessPolicies TeamAccessPolicies `json:"TeamAccessPolicies"`
		Namespaces         []string           `json:"Namespaces"`
	}

	// RegistryID represents a registry identifier
	RegistryID int

	// RegistryManagementConfiguration represents a configuration that can be used to query
	// the registry API via the registry management extension.
	RegistryManagementConfiguration struct {
		Type           RegistryType     `json:"Type"`
		Authentication bool             `json:"Authentication"`
		Username       string           `json:"Username"`
		Password       string           `json:"Password"`
		TLSConfig      TLSConfiguration `json:"TLSConfig"`
	}

	// RegistryType represents a type of registry
	RegistryType int

	// ResourceAccessLevel represents the level of control associated to a resource
	ResourceAccessLevel int

	// ResourceControl represent a reference to a Docker resource with specific access controls
	ResourceControl struct {
		// ResourceControl Identifier
		ID ResourceControlID `json:"Id" example:"1"`
		// Docker resource identifier on which access control will be applied.\
		// In the case of a resource control applied to a stack, use the stack name as identifier
		ResourceID string `json:"ResourceId" example:"617c5f22bb9b023d6daab7cba43a57576f83492867bc767d1c59416b065e5f08"`
		// List of Docker resources that will inherit this access control
		SubResourceIDs []string `json:"SubResourceIds" example:"617c5f22bb9b023d6daab7cba43a57576f83492867bc767d1c59416b065e5f08"`
		// Type of Docker resource. Valid values are: 1- container, 2 -service
		// 3 - volume, 4 - secret, 5 - stack, 6 - config or 7 - custom template
		Type         ResourceControlType  `json:"Type" example:"1"`
		UserAccesses []UserResourceAccess `json:"UserAccesses" example:""`
		TeamAccesses []TeamResourceAccess `json:"TeamAccesses" example:""`
		// Permit access to the associated resource to any user
		Public bool `json:"Public" example:"true"`
		// Permit access to resource only to admins
		AdministratorsOnly bool `json:"AdministratorsOnly" example:"true"`
		System             bool `json:"System" example:""`

		// Deprecated fields
		// Deprecated in DBVersion == 2
		OwnerID     UserID              `json:"OwnerId,omitempty"`
		AccessLevel ResourceAccessLevel `json:"AccessLevel,omitempty"`
	}

	// ResourceControlID represents a resource control identifier
	ResourceControlID int

	// ResourceControlType represents the type of resource associated to the resource control (volume, container, service...)
	ResourceControlType int

	// Role represents a set of authorizations that can be associated to a user or
	// to a team.
	Role struct {
		// Role Identifier
		ID RoleID `json:"Id" example:"1"`
		// Role name
		Name string `json:"Name" example:"HelpDesk"`
		// Role description
		Description string `json:"Description" example:"Read-only access of all resources in an environment(endpoint)"`
		// Authorizations associated to a role
		Authorizations Authorizations `json:"Authorizations"`
		Priority       int            `json:"Priority"`
	}

	// RoleID represents a role identifier
	RoleID int

	// Schedule represents a scheduled job.
	// It only contains a pointer to one of the JobRunner implementations
	// based on the JobType.
	// NOTE: The Recurring option is only used by ScriptExecutionJob at the moment
	// Deprecated in favor of EdgeJob
	Schedule struct {
		// Schedule Identifier
		ID             ScheduleID `json:"Id" example:"1"`
		Name           string
		CronExpression string
		Recurring      bool
		Created        int64
		JobType        JobType
		EdgeSchedule   *EdgeSchedule
	}

	// ScheduleID represents a schedule identifier.
	// Deprecated in favor of EdgeJob
	ScheduleID int

	// ScriptExecutionJob represents a scheduled job that can execute a script via a privileged container
	ScriptExecutionJob struct {
		Endpoints     []EndpointID
		Image         string
		ScriptPath    string
		RetryCount    int
		RetryInterval int
	}

	// Settings represents the application settings
	Settings struct {
		// URL to a logo that will be displayed on the login page as well as on top of the sidebar. Will use default Portainer logo when value is empty string
		LogoURL string `json:"LogoURL" example:"https://mycompany.mydomain.tld/logo.png"`
		// A list of label name & value that will be used to hide containers when querying containers
		BlackListedLabels []Pair `json:"BlackListedLabels"`
		// Active authentication method for the Portainer instance. Valid values are: 1 for internal, 2 for LDAP, or 3 for oauth
		AuthenticationMethod AuthenticationMethod `json:"AuthenticationMethod" example:"1"`
		LDAPSettings         LDAPSettings         `json:"LDAPSettings" example:""`
		OAuthSettings        OAuthSettings        `json:"OAuthSettings" example:""`
		// The interval in which environment(endpoint) snapshots are created
		SnapshotInterval string `json:"SnapshotInterval" example:"5m"`
		// URL to the templates that will be displayed in the UI when navigating to App Templates
		TemplatesURL string `json:"TemplatesURL" example:"https://raw.githubusercontent.com/portainer/templates/master/templates.json"`
		// The default check in interval for edge agent (in seconds)
		EdgeAgentCheckinInterval int `json:"EdgeAgentCheckinInterval" example:"5"`
		// Whether edge compute features are enabled
		EnableEdgeComputeFeatures bool `json:"EnableEdgeComputeFeatures" example:""`
		// The duration of a user session
		UserSessionTimeout string `json:"UserSessionTimeout" example:"5m"`
		// The expiry of a Kubeconfig
		KubeconfigExpiry string `json:"KubeconfigExpiry" example:"24h"`
		// Whether telemetry is enabled
		EnableTelemetry bool `json:"EnableTelemetry" example:"false"`
		// Helm repository URL, defaults to "https://charts.bitnami.com/bitnami"
		HelmRepositoryURL string `json:"HelmRepositoryURL" example:"https://charts.bitnami.com/bitnami"`
		// KubectlImage, defaults to portainer/kubectl-shell
		KubectlShellImage string `json:"KubectlShellImage" example:"portainer/kubectl-shell"`

		// Deprecated fields
		DisplayDonationHeader       bool
		DisplayExternalContributors bool

		// Deprecated fields v26
		EnableHostManagementFeatures              bool `json:"EnableHostManagementFeatures"`
		AllowVolumeBrowserForRegularUsers         bool `json:"AllowVolumeBrowserForRegularUsers"`
		AllowBindMountsForRegularUsers            bool `json:"AllowBindMountsForRegularUsers"`
		AllowPrivilegedModeForRegularUsers        bool `json:"AllowPrivilegedModeForRegularUsers"`
		AllowHostNamespaceForRegularUsers         bool `json:"AllowHostNamespaceForRegularUsers"`
		AllowStackManagementForRegularUsers       bool `json:"AllowStackManagementForRegularUsers"`
		AllowDeviceMappingForRegularUsers         bool `json:"AllowDeviceMappingForRegularUsers"`
		AllowContainerCapabilitiesForRegularUsers bool `json:"AllowContainerCapabilitiesForRegularUsers"`
	}

	// SnapshotJob represents a scheduled job that can create environment(endpoint) snapshots
	SnapshotJob struct{}

	// SoftwareEdition represents an edition of Portainer
	SoftwareEdition int

	// SSLSettings represents a pair of SSL certificate and key
	SSLSettings struct {
		CertPath    string `json:"certPath"`
		KeyPath     string `json:"keyPath"`
		SelfSigned  bool   `json:"selfSigned"`
		HTTPEnabled bool   `json:"httpEnabled"`
	}

	// Stack represents a Docker stack created via docker stack deploy
	Stack struct {
		// Stack Identifier
		ID StackID `json:"Id" example:"1"`
		// Stack name
		Name string `json:"Name" example:"myStack"`
		// Stack type. 1 for a Swarm stack, 2 for a Compose stack
		Type StackType `json:"Type" example:"2"`
		// Environment(Endpoint) identifier. Reference the environment(endpoint) that will be used for deployment
		EndpointID EndpointID `json:"EndpointId" example:"1"`
		// Cluster identifier of the Swarm cluster where the stack is deployed
		SwarmID string `json:"SwarmId" example:"jpofkc0i9uo9wtx1zesuk649w"`
		// Path to the Stack file
		EntryPoint string `json:"EntryPoint" example:"docker-compose.yml"`
		// A list of environment(endpoint) variables used during stack deployment
		Env []Pair `json:"Env" example:""`
		//
		ResourceControl *ResourceControl `json:"ResourceControl" example:""`
		// Stack status (1 - active, 2 - inactive)
		Status StackStatus `json:"Status" example:"1"`
		// Path on disk to the repository hosting the Stack file
		ProjectPath string `example:"/data/compose/myStack_jpofkc0i9uo9wtx1zesuk649w"`
		// The date in unix time when stack was created
		CreationDate int64 `example:"1587399600"`
		// The username which created this stack
		CreatedBy string `example:"admin"`
		// The date in unix time when stack was last updated
		UpdateDate int64 `example:"1587399600"`
		// The username which last updated this stack
		UpdatedBy string `example:"bob"`
		// Only applies when deploying stack with multiple files
		AdditionalFiles []string `json:"AdditionalFiles"`
		// The auto update settings of a git stack
		AutoUpdate *StackAutoUpdate `json:"AutoUpdate"`
		// The git config of this stack
		GitConfig *gittypes.RepoConfig
		// Kubernetes namespace if stack is a kube application
		Namespace string `example:"default"`
		// IsComposeFormat indicates if the Kubernetes stack is created from a Docker Compose file
		IsComposeFormat bool `example:"false"`
	}

	//StackAutoUpdate represents the git auto sync config for stack deployment
	StackAutoUpdate struct {
		// Auto update interval
		Interval string `example:"1m30s"`
		// A UUID generated from client
		Webhook string `example:"05de31a2-79fa-4644-9c12-faa67e5c49f0"`
		// Autoupdate job id
		JobID string `example:"15"`
	}

	// StackID represents a stack identifier (it must be composed of Name + "_" + SwarmID to create a unique identifier)
	StackID int

	// StackStatus represent a status for a stack
	StackStatus int

	// StackType represents the type of the stack (compose v2, stack deploy v3)
	StackType int


	// Status represents the application status
	Status struct {
		// Portainer API version
		Version string `json:"Version" example:"2.0.0"`
		// Server Instance ID
		InstanceID string `example:"299ab403-70a8-4c05-92f7-bf7a994d50df"`
	}

	// Tag represents a tag that can be associated to a resource
	Tag struct {
		// Tag identifier
		ID TagID `example:"1"`
		// Tag name
		Name string `json:"Name" example:"org/acme"`
		// A set of environment(endpoint) ids that have this tag
		Endpoints map[EndpointID]bool `json:"Endpoints"`
		// A set of environment(endpoint) group ids that have this tag
		EndpointGroups map[EndpointGroupID]bool `json:"EndpointGroups"`
	}

	// TagID represents a tag identifier
	TagID int

	// Team represents a list of user accounts
	Team struct {
		// Team Identifier
		ID TeamID `json:"Id" example:"1"`
		// Team name
		Name string `json:"Name" example:"developers"`
	}

	// TeamAccessPolicies represent the association of an access policy and a team
	TeamAccessPolicies map[TeamID]AccessPolicy

	// TeamID represents a team identifier
	TeamID int

	// TeamMembership represents a membership association between a user and a team
	TeamMembership struct {
		// Membership Identifier
		ID TeamMembershipID `json:"Id" example:"1"`
		// User identifier
		UserID UserID `json:"UserID" example:"1"`
		// Team identifier
		TeamID TeamID `json:"TeamID" example:"1"`
		// Team role (1 for team leader and 2 for team member)
		Role MembershipRole `json:"Role" example:"1"`
	}

	// TeamMembershipID represents a team membership identifier
	TeamMembershipID int

	// TeamResourceAccess represents the level of control on a resource for a specific team
	TeamResourceAccess struct {
		TeamID      TeamID              `json:"TeamId"`
		AccessLevel ResourceAccessLevel `json:"AccessLevel"`
	}

	// Template represents an application template that can be used as an App Template
	// or an Edge template
	Template struct {
		// Mandatory container/stack fields
		// Template Identifier
		ID TemplateID `json:"Id" example:"1"`
		// Template type. Valid values are: 1 (container), 2 (Swarm stack) or 3 (Compose stack)
		Type TemplateType `json:"type" example:"1"`
		// Title of the template
		Title string `json:"title" example:"Nginx"`
		// Description of the template
		Description string `json:"description" example:"High performance web server"`
		// Whether the template should be available to administrators only
		AdministratorOnly bool `json:"administrator_only" example:"true"`

		// Mandatory container fields
		// Image associated to a container template. Mandatory for a container template
		Image string `json:"image" example:"nginx:latest"`

		// Mandatory stack fields
		Repository TemplateRepository `json:"repository"`

		// Mandatory Edge stack fields
		// Stack file used for this template
		StackFile string `json:"stackFile"`

		// Optional stack/container fields
		// Default name for the stack/container to be used on deployment
		Name string `json:"name,omitempty" example:"mystackname"`
		// URL of the template's logo
		Logo string `json:"logo,omitempty" example:"https://cloudinovasi.id/assets/img/logos/nginx.png"`
		// A list of environment(endpoint) variables used during the template deployment
		Env []TemplateEnv `json:"env,omitempty"`
		// A note that will be displayed in the UI. Supports HTML content
		Note string `json:"note,omitempty" example:"This is my <b>custom</b> template"`
		// Platform associated to the template.
		// Valid values are: 'linux', 'windows' or leave empty for multi-platform
		Platform string `json:"platform,omitempty" example:"linux"`
		// A list of categories associated to the template
		Categories []string `json:"categories,omitempty" example:"database"`

		// Optional container fields
		// The URL of a registry associated to the image for a container template
		Registry string `json:"registry,omitempty" example:"quay.io"`
		// The command that will be executed in a container template
		Command string `json:"command,omitempty" example:"ls -lah"`
		// Name of a network that will be used on container deployment if it exists inside the environment(endpoint)
		Network string `json:"network,omitempty" example:"mynet"`
		// A list of volumes used during the container template deployment
		Volumes []TemplateVolume `json:"volumes,omitempty"`
		// A list of ports exposed by the container
		Ports []string `json:"ports,omitempty" example:"8080:80/tcp"`
		// Container labels
		Labels []Pair `json:"labels,omitempty" example:""`
		// Whether the container should be started in privileged mode
		Privileged bool `json:"privileged,omitempty" example:"true"`
		// Whether the container should be started in
		// interactive mode (-i -t equivalent on the CLI)
		Interactive bool `json:"interactive,omitempty" example:"true"`
		// Container restart policy
		RestartPolicy string `json:"restart_policy,omitempty" example:"on-failure"`
		// Container hostname
		Hostname string `json:"hostname,omitempty" example:"mycontainer"`
	}

	// TemplateEnv represents a template environment(endpoint) variable configuration
	TemplateEnv struct {
		// name of the environment(endpoint) variable
		Name string `json:"name" example:"MYSQL_ROOT_PASSWORD"`
		// Text for the label that will be generated in the UI
		Label string `json:"label,omitempty" example:"Root password"`
		// Content of the tooltip that will be generated in the UI
		Description string `json:"description,omitempty" example:"MySQL root account password"`
		// Default value that will be set for the variable
		Default string `json:"default,omitempty" example:"default_value"`
		// If set to true, will not generate any input for this variable in the UI
		Preset bool `json:"preset,omitempty" example:"false"`
		// A list of name/value that will be used to generate a dropdown in the UI
		Select []TemplateEnvSelect `json:"select,omitempty"`
	}

	// TemplateEnvSelect represents text/value pair that will be displayed as a choice for the
	// template user
	TemplateEnvSelect struct {
		// Some text that will displayed as a choice
		Text string `json:"text" example:"text value"`
		// A value that will be associated to the choice
		Value string `json:"value" example:"value"`
		// Will set this choice as the default choice
		Default bool `json:"default" example:"false"`
	}

	// TemplateID represents a template identifier
	TemplateID int

	// TemplateRepository represents the git repository configuration for a template
	TemplateRepository struct {
		// URL of a git repository used to deploy a stack template. Mandatory for a Swarm/Compose stack template
		URL string `json:"url" example:"https://github.com/portainer/portainer-compose"`
		// Path to the stack file inside the git repository
		StackFile string `json:"stackfile" example:"./subfolder/docker-compose.yml"`
	}

	// TemplateType represents the type of a template
	TemplateType int

	// TemplateVolume represents a template volume configuration
	TemplateVolume struct {
		// Path inside the container
		Container string `json:"container" example:"/data"`
		// Path on the host
		Bind string `json:"bind,omitempty" example:"/tmp"`
		// Whether the volume used should be readonly
		ReadOnly bool `json:"readonly,omitempty" example:"true"`
	}

	// TLSConfiguration represents a TLS configuration
	TLSConfiguration struct {
		// Use TLS
		TLS bool `json:"TLS" example:"true"`
		// Skip the verification of the server TLS certificate
		TLSSkipVerify bool `json:"TLSSkipVerify" example:"false"`
		// Path to the TLS CA certificate file
		TLSCACertPath string `json:"TLSCACert,omitempty" example:"/data/tls/ca.pem"`
		// Path to the TLS client certificate file
		TLSCertPath string `json:"TLSCert,omitempty" example:"/data/tls/cert.pem"`
		// Path to the TLS client key file
		TLSKeyPath string `json:"TLSKey,omitempty" example:"/data/tls/key.pem"`
	}

	// TLSFileType represents a type of TLS file required to connect to a Docker environment(endpoint).
	// It can be either a TLS CA file, a TLS certificate file or a TLS key file
	TLSFileType int

	// TokenData represents the data embedded in a JWT token
	TokenData struct {
		ID       UserID
		Username string
		Role     UserRole
	}

	// TunnelDetails represents information associated to a tunnel
	TunnelDetails struct {
		Status       string
		LastActivity time.Time
		Port         int
		Jobs         []EdgeJob
		Credentials  string
	}

	// TunnelServerInfo represents information associated to the tunnel server
	TunnelServerInfo struct {
		PrivateKeySeed string `json:"PrivateKeySeed"`
	}

	// User represents a user account
	User struct {
		// User Identifier
		ID       UserID `json:"Id" example:"1"`
		Username string `json:"Username" example:"bob"`
		Password string `json:"Password,omitempty" swaggerignore:"true"`
		// User Theme
		UserTheme string `example:"dark"`
		// User role (1 for administrator account and 2 for regular account)
		Role UserRole `json:"Role" example:"1"`

		// Deprecated fields
		// Deprecated in DBVersion == 25
		PortainerAuthorizations Authorizations         `json:"PortainerAuthorizations"`
		EndpointAuthorizations  EndpointAuthorizations `json:"EndpointAuthorizations"`
	}

	// UserAccessPolicies represent the association of an access policy and a user
	UserAccessPolicies map[UserID]AccessPolicy

	// UserID represents a user identifier
	UserID int

	// UserResourceAccess represents the level of control on a resource for a specific user
	UserResourceAccess struct {
		UserID      UserID              `json:"UserId"`
		AccessLevel ResourceAccessLevel `json:"AccessLevel"`
	}

	// UserRole represents the role of a user. It can be either an administrator
	// or a regular user
	UserRole int

	// Webhook represents a url webhook that can be used to update a service
	Webhook struct {
		// Webhook Identifier
		ID          WebhookID   `json:"Id" example:"1"`
		Token       string      `json:"Token"`
		ResourceID  string      `json:"ResourceId"`
		EndpointID  EndpointID  `json:"EndpointId"`
		WebhookType WebhookType `json:"Type"`
	}

	// WebhookID represents a webhook identifier.
	WebhookID int

	// WebhookType represents the type of resource a webhook is related to
	WebhookType int
)