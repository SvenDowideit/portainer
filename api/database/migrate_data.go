package database

import (
	"fmt"
	"github.com/portainer/portainer/api/cli"
	"github.com/portainer/portainer/api/database/migrator"
	"github.com/portainer/portainer/api/dataservices/errors"
	"github.com/portainer/portainer/api/internal/authorization"

	werrors "github.com/pkg/errors"
	portainer "github.com/portainer/portainer/api"
	plog "github.com/portainer/portainer/api/database/log"
)

const beforePortainerVersionUpgradeBackup = "portainer.db.bak"

var migrateLog = plog.NewScopedLog("database, migrate")

func (store *Store) MigrateData(force bool) error {
	if store.isNew && !force {
		return store.VersionService.StoreDBVersion(portainer.DBVersion)
	}

	version, err := store.version()
	if err != nil {
		return err
	}

	migratorParams := &migrator.MigratorParameters{
		DatabaseVersion:         version,
		EndpointGroupService:    store.EndpointGroupService,
		EndpointService:         store.EndpointService,
		EndpointRelationService: store.EndpointRelationService,
		ExtensionService:        store.ExtensionService,
		RegistryService:         store.RegistryService,
		ResourceControlService:  store.ResourceControlService,
		RoleService:             store.RoleService,
		ScheduleService:         store.ScheduleService,
		SettingsService:         store.SettingsService,
		StackService:            store.StackService,
		TagService:              store.TagService,
		TeamMembershipService:   store.TeamMembershipService,
		UserService:             store.UserService,
		VersionService:          store.VersionService,
		FileService:             store.fileService,
		DockerhubService:        store.DockerHubService,
		AuthorizationService:    authorization.NewService(store),
	}

	return store.connectionMigrateData(migratorParams, force)
}

// FailSafeMigrate backup and restore DB if migration fail
func (store *Store) FailSafeMigrate(migrator *migrator.Migrator) error {
	defer func() {
		if err := recover(); err != nil {
			migrateLog.Info(fmt.Sprintf("Error during migration, recovering [%v]", err))
			store.Rollback(true)
		}
	}()
	return migrator.Migrate()
}

// MigrateData automatically migrate the data based on the DBVersion.
// This process is only triggered on an existing database, not if the database was just created.
// if force is true, then migrate regardless.
func (store *Store) connectionMigrateData(migratorParams *migrator.MigratorParameters, force bool) error {
	migrator := migrator.NewMigrator(migratorParams, store.connection)

	// backup db file before upgrading DB to support rollback
	isUpdating, err := migratorParams.VersionService.IsUpdating()
	if err != nil && err != errors.ErrObjectNotFound {
		return err
	}

	if !isUpdating && migrator.Version() != portainer.DBVersion {
		err = store.backupVersion(migrator)
		if err != nil {
			return werrors.Wrapf(err, "failed to backup database")
		}
	}

	if migrator.Version() < portainer.DBVersion {
		migrateLog.Info(fmt.Sprintf("Migrating database from version %v to %v.\n", migrator.Version(), portainer.DBVersion))
		err = store.FailSafeMigrate(migrator)
		if err != nil {
			migrateLog.Error("An error occurred during database migration", err)
			return err
		}
	}

	return nil
}

// backupVersion will backup the database or panic if any errors occur
func (store *Store) backupVersion(migrator *migrator.Migrator) error {
	migrateLog.Info("Backing up database prior to version upgrade...")

	options := getBackupRestoreOptions(store.commonBackupDir())

	_, err := store.backupWithOptions(options)
	if err != nil {
		migrateLog.Error("An error occurred during database backup", err)
		removalErr := store.removeWithOptions(options)
		if removalErr != nil {
			migrateLog.Error("An error occurred during store removal prior to backup", err)
		}
		return err
	}

	return nil
}

// Rollback to a pre-upgrade backup copy/snapshot of portainer.db
func (store *Store) connectionRollback(force bool) error {

	if !force {
		confirmed, err := cli.Confirm("Are you sure you want to rollback your database to the previous backup?")
		if err != nil || !confirmed {
			return err
		}
	}

	options := getBackupRestoreOptions(store.commonBackupDir())

	err := store.restoreWithOptions(options)
	if err != nil {
		return err
	}

	return store.connection.Close()
}
