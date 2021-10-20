package access

import (
	"fmt"

	portainer "github.com/portainer/portainer/api"
	"github.com/portainer/portainer/api/datastore"
	"github.com/portainer/portainer/api/http/security"
)

func hasPermission(
	dataStore datastore.DataStore,
	userID portainer.UserID,
	endpointID portainer.EndpointID,
	registry *portainer.Registry,
) (hasPermission bool, err error) {
	user, err := dataStore.User().User(userID)
	if err != nil {
		return
	}

	if user.Role == portainer.AdministratorRole {
		return true, err
	}

	teamMemberships, err := dataStore.TeamMembership().TeamMembershipsByUserID(userID)
	if err != nil {
		return
	}

	hasPermission = security.AuthorizedRegistryAccess(registry, user, teamMemberships, endpointID)

	return
}

// GetAccessibleRegistry get the registry if the user has permission
func GetAccessibleRegistry(
	dataStore datastore.DataStore,
	userID portainer.UserID,
	endpointID portainer.EndpointID,
	registryID portainer.RegistryID,
) (registry *portainer.Registry, err error) {

	registry, err = dataStore.Registry().Registry(registryID)
	if err != nil {
		return
	}

	hasPermission, err := hasPermission(dataStore, userID, endpointID, registry)
	if err != nil {
		return
	}

	if !hasPermission {
		err = fmt.Errorf("user does not has permission to get the registry")
		return nil, err
	}

	return
}