package portainer

import (
	"context"
	"io"
	"time"

	v1 "k8s.io/api/core/v1"
	clientV1 "k8s.io/client-go/tools/clientcmd/api/v1"
)

type (
	// AccessPolicy represent a policy that can be associated to a user or team
	AccessPolicy struct {
		// Role identifier. Reference the role that will be associated to this access policy
		RoleID RoleID `json:"RoleId" example:"1"`
	}

	// AgentPlatform represents a platform type for an Agent
	AgentPlatform int

	// AuthenticationMethod represents the authentication method used to authenticate a user
	AuthenticationMethod int

	// Authorization represents an authorization associated to an operation
	Authorization string

	// Authorizations represents a set of authorizations associated to a role
	Authorizations map[Authorization]bool

	// AzureCredentials represents the credentials used to connect to an Azure
	// environment(endpoint).
	AzureCredentials struct {
		// Azure application ID
		ApplicationID string `json:"ApplicationID" example:"eag7cdo9-o09l-9i83-9dO9-f0b23oe78db4"`
		// Azure tenant ID
		TenantID string `json:"TenantID" example:"34ddc78d-4fel-2358-8cc1-df84c8o839f5"`
		// Azure authentication key
		AuthenticationKey string `json:"AuthenticationKey" example:"cOrXoK/1D35w8YQ8nH1/8ZGwzz45JIYD5jxHKXEQknk="`
	}

	// CLIFlags represents the available flags on the CLI
	CLIFlags struct {
		Addr                      *string
		AddrHTTPS                 *string
		TunnelAddr                *string
		TunnelPort                *string
		AdminPassword             *string
		AdminPasswordFile         *string
		Assets                    *string
		Data                      *string
		EnableEdgeComputeFeatures *bool
		EndpointURL               *string
		Labels                    *[]Pair
		Logo                      *string
		NoAnalytics               *bool
		Templates                 *string
		TLS                       *bool
		TLSSkipVerify             *bool
		TLSCacert                 *string
		TLSCert                   *string
		TLSKey                    *string
		HTTPDisabled              *bool
		SSL                       *bool
		SSLCert                   *string
		SSLKey                    *string
		Rollback                  *bool
		SnapshotInterval          *string
	}



	
	// CLIService represents a service for managing CLI
	CLIService interface {
		ParseFlags(version string) (*CLIFlags, error)
		ValidateFlags(flags *CLIFlags) error
	}

	// ComposeStackManager represents a service to manage Compose stacks
	ComposeStackManager interface {
		ComposeSyntaxMaxVersion() string
		NormalizeStackName(name string) string
		Up(ctx context.Context, stack *Stack, endpoint *Endpoint) error
		Down(ctx context.Context, stack *Stack, endpoint *Endpoint) error
	}

	// CryptoService represents a service for encrypting/hashing data
	CryptoService interface {
		Hash(data string) (string, error)
		CompareHashAndData(hash string, data string) error
	}


	// DigitalSignatureService represents a service to manage digital signatures
	DigitalSignatureService interface {
		ParseKeyPair(private, public []byte) error
		GenerateKeyPair() ([]byte, []byte, error)
		EncodedPublicKey() string
		PEMHeaders() (string, string)
		CreateSignature(message string) (string, error)
	}

	// DockerSnapshotter represents a service used to create Docker environment(endpoint) snapshots
	DockerSnapshotter interface {
		CreateSnapshot(endpoint *Endpoint) (*DockerSnapshot, error)
	}


	// FileService represents a service for managing files
	FileService interface {
		GetDockerConfigPath() string
		GetFileContent(trustedRootPath, filePath string) ([]byte, error)
		Copy(fromFilePath string, toFilePath string, deleteIfExists bool) error
		Rename(oldPath, newPath string) error
		RemoveDirectory(directoryPath string) error
		StoreTLSFileFromBytes(folder string, fileType TLSFileType, data []byte) (string, error)
		GetPathForTLSFile(folder string, fileType TLSFileType) (string, error)
		DeleteTLSFile(folder string, fileType TLSFileType) error
		DeleteTLSFiles(folder string) error
		GetStackProjectPath(stackIdentifier string) string
		StoreStackFileFromBytes(stackIdentifier, fileName string, data []byte) (string, error)
		GetEdgeStackProjectPath(edgeStackIdentifier string) string
		StoreEdgeStackFileFromBytes(edgeStackIdentifier, fileName string, data []byte) (string, error)
		StoreRegistryManagementFileFromBytes(folder, fileName string, data []byte) (string, error)
		KeyPairFilesExist() (bool, error)
		StoreKeyPair(private, public []byte, privatePEMHeader, publicPEMHeader string) error
		LoadKeyPair() ([]byte, []byte, error)
		WriteJSONToFile(path string, content interface{}) error
		FileExists(path string) (bool, error)
		StoreEdgeJobFileFromBytes(identifier string, data []byte) (string, error)
		GetEdgeJobFolder(identifier string) string
		ClearEdgeJobTaskLogs(edgeJobID, taskID string) error
		GetEdgeJobTaskLogFileContent(edgeJobID, taskID string) (string, error)
		StoreEdgeJobTaskLogFileFromBytes(edgeJobID, taskID string, data []byte) error
		GetBinaryFolder() string
		StoreCustomTemplateFileFromBytes(identifier, fileName string, data []byte) (string, error)
		GetCustomTemplateProjectPath(identifier string) string
		GetTemporaryPath() (string, error)
		GetDatastorePath() string
		GetDefaultSSLCertsPath() (string, string)
		StoreSSLCertPair(cert, key []byte) (string, string, error)
		CopySSLCertPair(certPath, keyPath string) (string, string, error)
	}

	// GitService represents a service for managing Git
	GitService interface {
		CloneRepository(destination string, repositoryURL, referenceName, username, password string) error
		LatestCommitID(repositoryURL, referenceName, username, password string) (string, error)
	}


	// JWTService represents a service for managing JWT tokens
	JWTService interface {
		GenerateToken(data *TokenData) (string, error)
		GenerateTokenForOAuth(data *TokenData, expiryTime *time.Time) (string, error)
		GenerateTokenForKubeconfig(data *TokenData) (string, error)
		ParseAndVerifyToken(token string) (*TokenData, error)
		SetUserSessionDuration(userSessionDuration time.Duration)
	}

	// KubeClient represents a service used to query a Kubernetes environment(endpoint)
	KubeClient interface {
		SetupUserServiceAccount(userID int, teamIDs []int, restrictDefaultNamespace bool) error
		GetServiceAccount(tokendata *TokenData) (*v1.ServiceAccount, error)
		GetServiceAccountBearerToken(userID int) (string, error)
		CreateUserShellPod(ctx context.Context, serviceAccountName, shellPodImage string) (*KubernetesShellPod, error)
		StartExecProcess(token string, useAdminToken bool, namespace, podName, containerName string, command []string, stdin io.Reader, stdout io.Writer, errChan chan error)
		NamespaceAccessPoliciesDeleteNamespace(namespace string) error
		GetNodesLimits() (K8sNodesLimits, error)
		GetNamespaceAccessPolicies() (map[string]K8sNamespaceAccessPolicy, error)
		UpdateNamespaceAccessPolicies(accessPolicies map[string]K8sNamespaceAccessPolicy) error
		DeleteRegistrySecret(registry *Registry, namespace string) error
		CreateRegistrySecret(registry *Registry, namespace string) error
		IsRegistrySecret(namespace, secretName string) (bool, error)
		GetKubeConfig(ctx context.Context, apiServerURL string, bearerToken string, tokenData *TokenData) (*clientV1.Config, error)
		ToggleSystemState(namespace string, isSystem bool) error
	}

	// KubernetesDeployer represents a service to deploy a manifest inside a Kubernetes environment(endpoint)
	KubernetesDeployer interface {
		Deploy(userID UserID, endpoint *Endpoint, manifestFiles []string, namespace string) (string, error)
		Remove(userID UserID, endpoint *Endpoint, manifestFiles []string, namespace string) (string, error)
		ConvertCompose(data []byte) ([]byte, error)
	}

	// KubernetesSnapshotter represents a service used to create Kubernetes environment(endpoint) snapshots
	KubernetesSnapshotter interface {
		CreateSnapshot(endpoint *Endpoint) (*KubernetesSnapshot, error)
	}

	// LDAPService represents a service used to authenticate users against a LDAP/AD
	LDAPService interface {
		AuthenticateUser(username, password string, settings *LDAPSettings) error
		TestConnectivity(settings *LDAPSettings) error
		GetUserGroups(username string, settings *LDAPSettings) ([]string, error)
		SearchGroups(settings *LDAPSettings) ([]LDAPUser, error)
		SearchUsers(settings *LDAPSettings) ([]string, error)
	}

	// OAuthService represents a service used to authenticate users using OAuth
	OAuthService interface {
		Authenticate(code string, configuration *OAuthSettings) (string, error)
	}


	// ReverseTunnelService represents a service used to manage reverse tunnel connections.
	ReverseTunnelService interface {
		StartTunnelServer(addr, port string, snapshotService SnapshotService) error
		StopTunnelServer() error
		GenerateEdgeKey(url, host string, endpointIdentifier int) string
		SetTunnelStatusToActive(endpointID EndpointID)
		SetTunnelStatusToRequired(endpointID EndpointID) error
		SetTunnelStatusToIdle(endpointID EndpointID)
		KeepTunnelAlive(endpointID EndpointID, ctx context.Context, maxKeepAlive time.Duration)
		GetTunnelDetails(endpointID EndpointID) *TunnelDetails
		GetActiveTunnel(endpoint *Endpoint) (*TunnelDetails, error)
		AddEdgeJob(endpointID EndpointID, edgeJob *EdgeJob)
		RemoveEdgeJob(edgeJobID EdgeJobID)
	}


	// Server defines the interface to serve the API
	Server interface {
		Start() error
	}


	// SnapshotService represents a service for managing environment(endpoint) snapshots
	SnapshotService interface {
		Start()
		Stop()
		SetSnapshotInterval(snapshotInterval string) error
		SnapshotEndpoint(endpoint *Endpoint) error
	}

	// SwarmStackManager represents a service to manage Swarm stacks
	SwarmStackManager interface {
		Login(registries []Registry, endpoint *Endpoint) error
		Logout(endpoint *Endpoint) error
		Deploy(stack *Stack, prune bool, endpoint *Endpoint) error
		Remove(stack *Stack, endpoint *Endpoint) error
		NormalizeStackName(name string) string
	}

)

const (
	// APIVersion is the version number of the Portainer API
	APIVersion = "2.9.3"
	// DBVersion is the version number of the Portainer database
	DBVersion = 33
	// ComposeSyntaxMaxVersion is a maximum supported version of the docker compose syntax
	ComposeSyntaxMaxVersion = "3.9"
	// AssetsServerURL represents the URL of the Portainer asset server
	AssetsServerURL = "https://portainer-io-assets.sfo2.digitaloceanspaces.com"
	// MessageOfTheDayURL represents the URL where Portainer MOTD message can be retrieved
	MessageOfTheDayURL = AssetsServerURL + "/motd.json"
	// VersionCheckURL represents the URL used to retrieve the latest version of Portainer
	VersionCheckURL = "https://api.github.com/repos/portainer/portainer/releases/latest"
	// PortainerAgentHeader represents the name of the header available in any agent response
	PortainerAgentHeader = "Portainer-Agent"
	// PortainerAgentEdgeIDHeader represent the name of the header containing the Edge ID associated to an agent/agent cluster
	PortainerAgentEdgeIDHeader = "X-PortainerAgent-EdgeID"
	// HTTPResponseAgentPlatform represents the name of the header containing the Agent platform
	HTTPResponseAgentPlatform = "Portainer-Agent-Platform"
	// PortainerAgentTargetHeader represent the name of the header containing the target node name
	PortainerAgentTargetHeader = "X-PortainerAgent-Target"
	// PortainerAgentSignatureHeader represent the name of the header containing the digital signature
	PortainerAgentSignatureHeader = "X-PortainerAgent-Signature"
	// PortainerAgentPublicKeyHeader represent the name of the header containing the public key
	PortainerAgentPublicKeyHeader = "X-PortainerAgent-PublicKey"
	// PortainerAgentKubernetesSATokenHeader represent the name of the header containing a Kubernetes SA token
	PortainerAgentKubernetesSATokenHeader = "X-PortainerAgent-SA-Token"
	// PortainerAgentSignatureMessage represents the message used to create a digital signature
	// to be used when communicating with an agent
	PortainerAgentSignatureMessage = "Portainer-App"
	// DefaultEdgeAgentCheckinIntervalInSeconds represents the default interval (in seconds) used by Edge agents to checkin with the Portainer instance
	DefaultEdgeAgentCheckinIntervalInSeconds = 5
	// DefaultTemplatesURL represents the URL to the official templates supported by Portainer
	DefaultTemplatesURL = "https://raw.githubusercontent.com/portainer/templates/master/templates-2.0.json"
	// DefaultHelmrepositoryURL represents the URL to the official templates supported by Bitnami
	DefaultHelmRepositoryURL = "https://charts.bitnami.com/bitnami"
	// DefaultUserSessionTimeout represents the default timeout after which the user session is cleared
	DefaultUserSessionTimeout = "8h"
	// DefaultUserSessionTimeout represents the default timeout after which the user session is cleared
	DefaultKubeconfigExpiry = "0"
	// DefaultKubectlShellImage represents the default image and tag for the kubectl shell
	DefaultKubectlShellImage = "portainer/kubectl-shell"
	// WebSocketKeepAlive web socket keep alive for edge environments
	WebSocketKeepAlive = 1 * time.Hour
)

const (
	_ AuthenticationMethod = iota
	// AuthenticationInternal represents the internal authentication method (authentication against Portainer API)
	AuthenticationInternal
	// AuthenticationLDAP represents the LDAP authentication method (authentication against a LDAP server)
	AuthenticationLDAP
	//AuthenticationOAuth represents the OAuth authentication method (authentication against a authorization server)
	AuthenticationOAuth
)

const (
	_ AgentPlatform = iota
	// AgentPlatformDocker represent the Docker platform (Standalone/Swarm)
	AgentPlatformDocker
	// AgentPlatformKubernetes represent the Kubernetes platform
	AgentPlatformKubernetes
)

const (
	_ EdgeJobLogsStatus = iota
	// EdgeJobLogsStatusIdle represents an idle log collection job
	EdgeJobLogsStatusIdle
	// EdgeJobLogsStatusPending represents a pending log collection job
	EdgeJobLogsStatusPending
	// EdgeJobLogsStatusCollected represents a completed log collection job
	EdgeJobLogsStatusCollected
)

const (
	_ CustomTemplatePlatform = iota
	// CustomTemplatePlatformLinux represents a custom template for linux
	CustomTemplatePlatformLinux
	// CustomTemplatePlatformWindows represents a custom template for windows
	CustomTemplatePlatformWindows
)

const (
	// EdgeStackDeploymentCompose represent an edge stack deployed using a compose file
	EdgeStackDeploymentCompose EdgeStackDeploymentType = iota
	// EdgeStackDeploymentKubernetes represent an edge stack deployed using a kubernetes manifest file
	EdgeStackDeploymentKubernetes
)

const (
	_ EdgeStackStatusType = iota
	//StatusOk represents a successfully deployed edge stack
	StatusOk
	//StatusError represents an edge environment(endpoint) which failed to deploy its edge stack
	StatusError
	//StatusAcknowledged represents an acknowledged edge stack
	StatusAcknowledged
)

const (
	_ EndpointExtensionType = iota
	// StoridgeEndpointExtension represents the Storidge extension
	StoridgeEndpointExtension
)

const (
	_ EndpointStatus = iota
	// EndpointStatusUp is used to represent an available environment(endpoint)
	EndpointStatusUp
	// EndpointStatusDown is used to represent an unavailable environment(endpoint)
	EndpointStatusDown
)

const (
	_ EndpointType = iota
	// DockerEnvironment represents an environment(endpoint) connected to a Docker environment(endpoint)
	DockerEnvironment
	// AgentOnDockerEnvironment represents an environment(endpoint) connected to a Portainer agent deployed on a Docker environment(endpoint)
	AgentOnDockerEnvironment
	// AzureEnvironment represents an environment(endpoint) connected to an Azure environment(endpoint)
	AzureEnvironment
	// EdgeAgentOnDockerEnvironment represents an environment(endpoint) connected to an Edge agent deployed on a Docker environment(endpoint)
	EdgeAgentOnDockerEnvironment
	// KubernetesLocalEnvironment represents an environment(endpoint) connected to a local Kubernetes environment(endpoint)
	KubernetesLocalEnvironment
	// AgentOnKubernetesEnvironment represents an environment(endpoint) connected to a Portainer agent deployed on a Kubernetes environment(endpoint)
	AgentOnKubernetesEnvironment
	// EdgeAgentOnKubernetesEnvironment represents an environment(endpoint) connected to an Edge agent deployed on a Kubernetes environment(endpoint)
	EdgeAgentOnKubernetesEnvironment
)

const (
	_ JobType = iota
	// SnapshotJobType is a system job used to create environment(endpoint) snapshots
	SnapshotJobType = 2
)

const (
	_ MembershipRole = iota
	// TeamLeader represents a leader role inside a team
	TeamLeader
	// TeamMember represents a member role inside a team
	TeamMember
)

const (
	_ SoftwareEdition = iota
	// PortainerCE represents the community edition of Portainer
	PortainerCE
	// PortainerBE represents the business edition of Portainer
	PortainerBE
	// PortainerEE represents the business edition of Portainer
	PortainerEE
)

const (
	_ RegistryType = iota
	// QuayRegistry represents a Quay.io registry
	QuayRegistry
	// AzureRegistry represents an ACR registry
	AzureRegistry
	// CustomRegistry represents a custom registry
	CustomRegistry
	// GitlabRegistry represents a gitlab registry
	GitlabRegistry
	// ProGetRegistry represents a proget registry
	ProGetRegistry
	// DockerHubRegistry represents a dockerhub registry
	DockerHubRegistry
)

const (
	_ ResourceAccessLevel = iota
	// ReadWriteAccessLevel represents an access level with read-write permissions on a resource
	ReadWriteAccessLevel
)

const (
	_ ResourceControlType = iota
	// ContainerResourceControl represents a resource control associated to a Docker container
	ContainerResourceControl
	// ServiceResourceControl represents a resource control associated to a Docker service
	ServiceResourceControl
	// VolumeResourceControl represents a resource control associated to a Docker volume
	VolumeResourceControl
	// NetworkResourceControl represents a resource control associated to a Docker network
	NetworkResourceControl
	// SecretResourceControl represents a resource control associated to a Docker secret
	SecretResourceControl
	// StackResourceControl represents a resource control associated to a stack composed of Docker services
	StackResourceControl
	// ConfigResourceControl represents a resource control associated to a Docker config
	ConfigResourceControl
	// CustomTemplateResourceControl represents a resource control associated to a custom template
	CustomTemplateResourceControl
	// ContainerGroupResourceControl represents a resource control associated to an Azure container group
	ContainerGroupResourceControl
)

const (
	_ StackType = iota
	// DockerSwarmStack represents a stack managed via docker stack
	DockerSwarmStack
	// DockerComposeStack represents a stack managed via docker-compose
	DockerComposeStack
	// KubernetesStack represents a stack managed via kubectl
	KubernetesStack
)

// StackStatus represents a status for a stack
const (
	_ StackStatus = iota
	StackStatusActive
	StackStatusInactive
)

const (
	_ TemplateType = iota
	// ContainerTemplate represents a container template
	ContainerTemplate
	// SwarmStackTemplate represents a template used to deploy a Swarm stack
	SwarmStackTemplate
	// ComposeStackTemplate represents a template used to deploy a Compose stack
	ComposeStackTemplate
	// EdgeStackTemplate represents a template used to deploy an Edge stack
	EdgeStackTemplate
)

const (
	// TLSFileCA represents a TLS CA certificate file
	TLSFileCA TLSFileType = iota
	// TLSFileCert represents a TLS certificate file
	TLSFileCert
	// TLSFileKey represents a TLS key file
	TLSFileKey
)

const (
	_ UserRole = iota
	// AdministratorRole represents an administrator user role
	AdministratorRole
	// StandardUserRole represents a regular user role
	StandardUserRole
)

const (
	_ WebhookType = iota
	// ServiceWebhook is a webhook for restarting a docker service
	ServiceWebhook
)

const (
	// EdgeAgentIdle represents an idle state for a tunnel connected to an Edge environment(endpoint).
	EdgeAgentIdle string = "IDLE"
	// EdgeAgentManagementRequired represents a required state for a tunnel connected to an Edge environment(endpoint)
	EdgeAgentManagementRequired string = "REQUIRED"
	// EdgeAgentActive represents an active state for a tunnel connected to an Edge environment(endpoint)
	EdgeAgentActive string = "ACTIVE"
)

// represents an authorization type
const (
	OperationDockerContainerArchiveInfo         Authorization = "DockerContainerArchiveInfo"
	OperationDockerContainerList                Authorization = "DockerContainerList"
	OperationDockerContainerExport              Authorization = "DockerContainerExport"
	OperationDockerContainerChanges             Authorization = "DockerContainerChanges"
	OperationDockerContainerInspect             Authorization = "DockerContainerInspect"
	OperationDockerContainerTop                 Authorization = "DockerContainerTop"
	OperationDockerContainerLogs                Authorization = "DockerContainerLogs"
	OperationDockerContainerStats               Authorization = "DockerContainerStats"
	OperationDockerContainerAttachWebsocket     Authorization = "DockerContainerAttachWebsocket"
	OperationDockerContainerArchive             Authorization = "DockerContainerArchive"
	OperationDockerContainerCreate              Authorization = "DockerContainerCreate"
	OperationDockerContainerPrune               Authorization = "DockerContainerPrune"
	OperationDockerContainerKill                Authorization = "DockerContainerKill"
	OperationDockerContainerPause               Authorization = "DockerContainerPause"
	OperationDockerContainerUnpause             Authorization = "DockerContainerUnpause"
	OperationDockerContainerRestart             Authorization = "DockerContainerRestart"
	OperationDockerContainerStart               Authorization = "DockerContainerStart"
	OperationDockerContainerStop                Authorization = "DockerContainerStop"
	OperationDockerContainerWait                Authorization = "DockerContainerWait"
	OperationDockerContainerResize              Authorization = "DockerContainerResize"
	OperationDockerContainerAttach              Authorization = "DockerContainerAttach"
	OperationDockerContainerExec                Authorization = "DockerContainerExec"
	OperationDockerContainerRename              Authorization = "DockerContainerRename"
	OperationDockerContainerUpdate              Authorization = "DockerContainerUpdate"
	OperationDockerContainerPutContainerArchive Authorization = "DockerContainerPutContainerArchive"
	OperationDockerContainerDelete              Authorization = "DockerContainerDelete"
	OperationDockerImageList                    Authorization = "DockerImageList"
	OperationDockerImageSearch                  Authorization = "DockerImageSearch"
	OperationDockerImageGetAll                  Authorization = "DockerImageGetAll"
	OperationDockerImageGet                     Authorization = "DockerImageGet"
	OperationDockerImageHistory                 Authorization = "DockerImageHistory"
	OperationDockerImageInspect                 Authorization = "DockerImageInspect"
	OperationDockerImageLoad                    Authorization = "DockerImageLoad"
	OperationDockerImageCreate                  Authorization = "DockerImageCreate"
	OperationDockerImagePrune                   Authorization = "DockerImagePrune"
	OperationDockerImagePush                    Authorization = "DockerImagePush"
	OperationDockerImageTag                     Authorization = "DockerImageTag"
	OperationDockerImageDelete                  Authorization = "DockerImageDelete"
	OperationDockerImageCommit                  Authorization = "DockerImageCommit"
	OperationDockerImageBuild                   Authorization = "DockerImageBuild"
	OperationDockerNetworkList                  Authorization = "DockerNetworkList"
	OperationDockerNetworkInspect               Authorization = "DockerNetworkInspect"
	OperationDockerNetworkCreate                Authorization = "DockerNetworkCreate"
	OperationDockerNetworkConnect               Authorization = "DockerNetworkConnect"
	OperationDockerNetworkDisconnect            Authorization = "DockerNetworkDisconnect"
	OperationDockerNetworkPrune                 Authorization = "DockerNetworkPrune"
	OperationDockerNetworkDelete                Authorization = "DockerNetworkDelete"
	OperationDockerVolumeList                   Authorization = "DockerVolumeList"
	OperationDockerVolumeInspect                Authorization = "DockerVolumeInspect"
	OperationDockerVolumeCreate                 Authorization = "DockerVolumeCreate"
	OperationDockerVolumePrune                  Authorization = "DockerVolumePrune"
	OperationDockerVolumeDelete                 Authorization = "DockerVolumeDelete"
	OperationDockerExecInspect                  Authorization = "DockerExecInspect"
	OperationDockerExecStart                    Authorization = "DockerExecStart"
	OperationDockerExecResize                   Authorization = "DockerExecResize"
	OperationDockerSwarmInspect                 Authorization = "DockerSwarmInspect"
	OperationDockerSwarmUnlockKey               Authorization = "DockerSwarmUnlockKey"
	OperationDockerSwarmInit                    Authorization = "DockerSwarmInit"
	OperationDockerSwarmJoin                    Authorization = "DockerSwarmJoin"
	OperationDockerSwarmLeave                   Authorization = "DockerSwarmLeave"
	OperationDockerSwarmUpdate                  Authorization = "DockerSwarmUpdate"
	OperationDockerSwarmUnlock                  Authorization = "DockerSwarmUnlock"
	OperationDockerNodeList                     Authorization = "DockerNodeList"
	OperationDockerNodeInspect                  Authorization = "DockerNodeInspect"
	OperationDockerNodeUpdate                   Authorization = "DockerNodeUpdate"
	OperationDockerNodeDelete                   Authorization = "DockerNodeDelete"
	OperationDockerServiceList                  Authorization = "DockerServiceList"
	OperationDockerServiceInspect               Authorization = "DockerServiceInspect"
	OperationDockerServiceLogs                  Authorization = "DockerServiceLogs"
	OperationDockerServiceCreate                Authorization = "DockerServiceCreate"
	OperationDockerServiceUpdate                Authorization = "DockerServiceUpdate"
	OperationDockerServiceDelete                Authorization = "DockerServiceDelete"
	OperationDockerSecretList                   Authorization = "DockerSecretList"
	OperationDockerSecretInspect                Authorization = "DockerSecretInspect"
	OperationDockerSecretCreate                 Authorization = "DockerSecretCreate"
	OperationDockerSecretUpdate                 Authorization = "DockerSecretUpdate"
	OperationDockerSecretDelete                 Authorization = "DockerSecretDelete"
	OperationDockerConfigList                   Authorization = "DockerConfigList"
	OperationDockerConfigInspect                Authorization = "DockerConfigInspect"
	OperationDockerConfigCreate                 Authorization = "DockerConfigCreate"
	OperationDockerConfigUpdate                 Authorization = "DockerConfigUpdate"
	OperationDockerConfigDelete                 Authorization = "DockerConfigDelete"
	OperationDockerTaskList                     Authorization = "DockerTaskList"
	OperationDockerTaskInspect                  Authorization = "DockerTaskInspect"
	OperationDockerTaskLogs                     Authorization = "DockerTaskLogs"
	OperationDockerPluginList                   Authorization = "DockerPluginList"
	OperationDockerPluginPrivileges             Authorization = "DockerPluginPrivileges"
	OperationDockerPluginInspect                Authorization = "DockerPluginInspect"
	OperationDockerPluginPull                   Authorization = "DockerPluginPull"
	OperationDockerPluginCreate                 Authorization = "DockerPluginCreate"
	OperationDockerPluginEnable                 Authorization = "DockerPluginEnable"
	OperationDockerPluginDisable                Authorization = "DockerPluginDisable"
	OperationDockerPluginPush                   Authorization = "DockerPluginPush"
	OperationDockerPluginUpgrade                Authorization = "DockerPluginUpgrade"
	OperationDockerPluginSet                    Authorization = "DockerPluginSet"
	OperationDockerPluginDelete                 Authorization = "DockerPluginDelete"
	OperationDockerSessionStart                 Authorization = "DockerSessionStart"
	OperationDockerDistributionInspect          Authorization = "DockerDistributionInspect"
	OperationDockerBuildPrune                   Authorization = "DockerBuildPrune"
	OperationDockerBuildCancel                  Authorization = "DockerBuildCancel"
	OperationDockerPing                         Authorization = "DockerPing"
	OperationDockerInfo                         Authorization = "DockerInfo"
	OperationDockerEvents                       Authorization = "DockerEvents"
	OperationDockerSystem                       Authorization = "DockerSystem"
	OperationDockerVersion                      Authorization = "DockerVersion"

	OperationDockerAgentPing         Authorization = "DockerAgentPing"
	OperationDockerAgentList         Authorization = "DockerAgentList"
	OperationDockerAgentHostInfo     Authorization = "DockerAgentHostInfo"
	OperationDockerAgentBrowseDelete Authorization = "DockerAgentBrowseDelete"
	OperationDockerAgentBrowseGet    Authorization = "DockerAgentBrowseGet"
	OperationDockerAgentBrowseList   Authorization = "DockerAgentBrowseList"
	OperationDockerAgentBrowsePut    Authorization = "DockerAgentBrowsePut"
	OperationDockerAgentBrowseRename Authorization = "DockerAgentBrowseRename"

	OperationPortainerDockerHubInspect        Authorization = "PortainerDockerHubInspect"
	OperationPortainerDockerHubUpdate         Authorization = "PortainerDockerHubUpdate"
	OperationPortainerEndpointGroupCreate     Authorization = "PortainerEndpointGroupCreate"
	OperationPortainerEndpointGroupList       Authorization = "PortainerEndpointGroupList"
	OperationPortainerEndpointGroupDelete     Authorization = "PortainerEndpointGroupDelete"
	OperationPortainerEndpointGroupInspect    Authorization = "PortainerEndpointGroupInspect"
	OperationPortainerEndpointGroupUpdate     Authorization = "PortainerEndpointGroupEdit"
	OperationPortainerEndpointGroupAccess     Authorization = "PortainerEndpointGroupAccess "
	OperationPortainerEndpointList            Authorization = "PortainerEndpointList"
	OperationPortainerEndpointInspect         Authorization = "PortainerEndpointInspect"
	OperationPortainerEndpointCreate          Authorization = "PortainerEndpointCreate"
	OperationPortainerEndpointExtensionAdd    Authorization = "PortainerEndpointExtensionAdd"
	OperationPortainerEndpointJob             Authorization = "PortainerEndpointJob"
	OperationPortainerEndpointSnapshots       Authorization = "PortainerEndpointSnapshots"
	OperationPortainerEndpointSnapshot        Authorization = "PortainerEndpointSnapshot"
	OperationPortainerEndpointUpdate          Authorization = "PortainerEndpointUpdate"
	OperationPortainerEndpointUpdateAccess    Authorization = "PortainerEndpointUpdateAccess"
	OperationPortainerEndpointDelete          Authorization = "PortainerEndpointDelete"
	OperationPortainerEndpointExtensionRemove Authorization = "PortainerEndpointExtensionRemove"
	OperationPortainerExtensionList           Authorization = "PortainerExtensionList"
	OperationPortainerExtensionInspect        Authorization = "PortainerExtensionInspect"
	OperationPortainerExtensionCreate         Authorization = "PortainerExtensionCreate"
	OperationPortainerExtensionUpdate         Authorization = "PortainerExtensionUpdate"
	OperationPortainerExtensionDelete         Authorization = "PortainerExtensionDelete"
	OperationPortainerMOTD                    Authorization = "PortainerMOTD"
	OperationPortainerRegistryList            Authorization = "PortainerRegistryList"
	OperationPortainerRegistryInspect         Authorization = "PortainerRegistryInspect"
	OperationPortainerRegistryCreate          Authorization = "PortainerRegistryCreate"
	OperationPortainerRegistryConfigure       Authorization = "PortainerRegistryConfigure"
	OperationPortainerRegistryUpdate          Authorization = "PortainerRegistryUpdate"
	OperationPortainerRegistryUpdateAccess    Authorization = "PortainerRegistryUpdateAccess"
	OperationPortainerRegistryDelete          Authorization = "PortainerRegistryDelete"
	OperationPortainerResourceControlCreate   Authorization = "PortainerResourceControlCreate"
	OperationPortainerResourceControlUpdate   Authorization = "PortainerResourceControlUpdate"
	OperationPortainerResourceControlDelete   Authorization = "PortainerResourceControlDelete"
	OperationPortainerRoleList                Authorization = "PortainerRoleList"
	OperationPortainerRoleInspect             Authorization = "PortainerRoleInspect"
	OperationPortainerRoleCreate              Authorization = "PortainerRoleCreate"
	OperationPortainerRoleUpdate              Authorization = "PortainerRoleUpdate"
	OperationPortainerRoleDelete              Authorization = "PortainerRoleDelete"
	OperationPortainerScheduleList            Authorization = "PortainerScheduleList"
	OperationPortainerScheduleInspect         Authorization = "PortainerScheduleInspect"
	OperationPortainerScheduleFile            Authorization = "PortainerScheduleFile"
	OperationPortainerScheduleTasks           Authorization = "PortainerScheduleTasks"
	OperationPortainerScheduleCreate          Authorization = "PortainerScheduleCreate"
	OperationPortainerScheduleUpdate          Authorization = "PortainerScheduleUpdate"
	OperationPortainerScheduleDelete          Authorization = "PortainerScheduleDelete"
	OperationPortainerSettingsInspect         Authorization = "PortainerSettingsInspect"
	OperationPortainerSettingsUpdate          Authorization = "PortainerSettingsUpdate"
	OperationPortainerSettingsLDAPCheck       Authorization = "PortainerSettingsLDAPCheck"
	OperationPortainerStackList               Authorization = "PortainerStackList"
	OperationPortainerStackInspect            Authorization = "PortainerStackInspect"
	OperationPortainerStackFile               Authorization = "PortainerStackFile"
	OperationPortainerStackCreate             Authorization = "PortainerStackCreate"
	OperationPortainerStackMigrate            Authorization = "PortainerStackMigrate"
	OperationPortainerStackUpdate             Authorization = "PortainerStackUpdate"
	OperationPortainerStackDelete             Authorization = "PortainerStackDelete"
	OperationPortainerTagList                 Authorization = "PortainerTagList"
	OperationPortainerTagCreate               Authorization = "PortainerTagCreate"
	OperationPortainerTagDelete               Authorization = "PortainerTagDelete"
	OperationPortainerTeamMembershipList      Authorization = "PortainerTeamMembershipList"
	OperationPortainerTeamMembershipCreate    Authorization = "PortainerTeamMembershipCreate"
	OperationPortainerTeamMembershipUpdate    Authorization = "PortainerTeamMembershipUpdate"
	OperationPortainerTeamMembershipDelete    Authorization = "PortainerTeamMembershipDelete"
	OperationPortainerTeamList                Authorization = "PortainerTeamList"
	OperationPortainerTeamInspect             Authorization = "PortainerTeamInspect"
	OperationPortainerTeamMemberships         Authorization = "PortainerTeamMemberships"
	OperationPortainerTeamCreate              Authorization = "PortainerTeamCreate"
	OperationPortainerTeamUpdate              Authorization = "PortainerTeamUpdate"
	OperationPortainerTeamDelete              Authorization = "PortainerTeamDelete"
	OperationPortainerTemplateList            Authorization = "PortainerTemplateList"
	OperationPortainerTemplateInspect         Authorization = "PortainerTemplateInspect"
	OperationPortainerTemplateCreate          Authorization = "PortainerTemplateCreate"
	OperationPortainerTemplateUpdate          Authorization = "PortainerTemplateUpdate"
	OperationPortainerTemplateDelete          Authorization = "PortainerTemplateDelete"
	OperationPortainerUploadTLS               Authorization = "PortainerUploadTLS"
	OperationPortainerUserList                Authorization = "PortainerUserList"
	OperationPortainerUserInspect             Authorization = "PortainerUserInspect"
	OperationPortainerUserMemberships         Authorization = "PortainerUserMemberships"
	OperationPortainerUserCreate              Authorization = "PortainerUserCreate"
	OperationPortainerUserUpdate              Authorization = "PortainerUserUpdate"
	OperationPortainerUserUpdatePassword      Authorization = "PortainerUserUpdatePassword"
	OperationPortainerUserDelete              Authorization = "PortainerUserDelete"
	OperationPortainerWebsocketExec           Authorization = "PortainerWebsocketExec"
	OperationPortainerWebhookList             Authorization = "PortainerWebhookList"
	OperationPortainerWebhookCreate           Authorization = "PortainerWebhookCreate"
	OperationPortainerWebhookDelete           Authorization = "PortainerWebhookDelete"

	OperationIntegrationStoridgeAdmin Authorization = "IntegrationStoridgeAdmin"

	OperationDockerUndefined      Authorization = "DockerUndefined"
	OperationDockerAgentUndefined Authorization = "DockerAgentUndefined"
	OperationPortainerUndefined   Authorization = "PortainerUndefined"

	EndpointResourcesAccess Authorization = "EndpointResourcesAccess"
)

const (
	AzurePathContainerGroups = "/subscriptions/*/providers/Microsoft.ContainerInstance/containerGroups"
	AzurePathContainerGroup  = "/subscriptions/*/resourceGroups/*/providers/Microsoft.ContainerInstance/containerGroups/*"
)
