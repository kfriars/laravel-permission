<?php

namespace Spatie\Permission\Traits;

use Spatie\Permission\Guard;
use Illuminate\Support\Collection;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Spatie\Permission\WildcardPermission;
use Spatie\Permission\PermissionRegistrar;
use Spatie\Permission\Contracts\Permission;
use Spatie\Permission\Exceptions\GuardDoesNotMatch;
use Illuminate\Database\Eloquent\Relations\MorphToMany;
use Spatie\Permission\Exceptions\PermissionDoesNotExist;
use Spatie\Permission\Exceptions\WildcardPermissionInvalidArgument;

trait HasPermissions
{
    private $permissionClass;
    private $usesPermissions = true;

    public static function bootHasPermissions()
    {
        static::deleting(function ($model) {
            if (method_exists($model, 'isForceDeleting') && ! $model->isForceDeleting()) {
                return;
            }

            $model->permissions()->detach();
        });
    }

    public function getPermissionClass()
    {
        if (! isset($this->permissionClass)) {
            $this->permissionClass = app(PermissionRegistrar::class)->getPermissionClass();
        }

        return $this->permissionClass;
    }

    /**
     * The model's permissions for every context.
     */
    public function permissions() : MorphToMany
    {
        return $this->morphToMany(
            config('permission.models.permission'),
            'model',
            config('permission.table_names.model_has_permissions'),
            config('permission.column_names.model_morph_key'),
            'permission_id'
        )->withPivot([
            'context_type',
            'context_id'
        ]);
    }

    /**
     * The model's global permissions.
     */
    public function globalPermissions(): MorphToMany
    {
        return $this->permissionsFor(null);
    }

    /**
     * The Model's permissions for a context.
     */
    public function permissionsFor(?Model $context) : MorphToMany
    {
        if ($context === null) {
            return $this->permissions()
                        ->wherePivot('context_type', 'global')
                        ->wherePivot('context_id', 0)
                        ->withPivot([
                            'context_type',
                            'context_id'
                        ]);
        }

        $contextType = (new \ReflectionClass($context))->getName();

        return $this->permissions()
                    ->wherePivot('context_type', $contextType)
                    ->wherePivot('context_id', $context->id)
                    ->withPivot([
                        'context_type',
                        'context_id'
                    ]);
    }

    /**
     * Scope the model query to certain permissions only.
     *
     * @param \Illuminate\Database\Eloquent\Builder $query
     * @param string|array|\Spatie\Permission\Contracts\Permission|\Illuminate\Support\Collection $permissions
     *
     * @return \Illuminate\Database\Eloquent\Builder
     */
    public function scopePermission(Builder $query, $permissions): Builder
    {
        return $this->scopePermissionFor(null, $query, $permissions);
    }

    /**
     * Scope the model query to certain permissions only given the context.
     *
     * @param null|Model $context
     * @param \Illuminate\Database\Eloquent\Builder $query
     * @param string|array|\Spatie\Permission\Contracts\Permission|\Illuminate\Support\Collection $permissions
     *
     * @return \Illuminate\Database\Eloquent\Builder
     */
    public function scopePermissionFor(?Model $context, Builder $query, $permissions): Builder
    {
        if ($context === null) {
            $contextType = 'global';
        } else {
            $contextType = (new \ReflectionClass($context))->getName();
        }

        $permissions = $this->convertToPermissionModels($permissions);
        
        $rolesWithPermissions = array_unique(array_reduce($permissions, function ($result, $permission) use ($context) {
                return array_merge($result, $permission->rolesFor($context)->get()->all());
        }, []));
        try {
        return $query->where(function (Builder $query) use ($permissions, $rolesWithPermissions, $contextType) {
            $query->whereHas('permissions', function (Builder $subQuery) use ($permissions, $contextType) {
                $subQuery->whereIn(config('permission.table_names.permissions').'.id', \array_column($permissions, 'id'))
                         ->where(config('permission.table_names.permissions').'.context_type', $contextType);
            });
            if (count($rolesWithPermissions) > 0) {
                $query->orWhereHas('roles', function (Builder $subQuery) use ($rolesWithPermissions, $contextType) {
                    $subQuery->whereIn(config('permission.table_names.roles').'.id', \array_column($rolesWithPermissions, 'id'))
                             ->where(config('permission.table_names.roles').'.context_type', $contextType);
                });
            }
        });
        } catch (\Exception $e) {
            dd('They see us brooooinnnn');
        }
    }

    /**
     * @param string|array|\Spatie\Permission\Contracts\Permission|\Illuminate\Support\Collection $permissions
     *
     * @return array
     */
    protected function convertToPermissionModels($permissions): array
    {
        return $this->convertToPermissionModelsFor(null, $permissions);
    }

    /**
     * @param null|Model $context
     * @param string|array|\Spatie\Permission\Contracts\Permission|\Illuminate\Support\Collection $permissions
     *
     * @return array
     */
    protected function convertToPermissionModelsFor(?Model $context, $permissions): array
    {
        if ($permissions instanceof Collection) {
            $permissions = $permissions->all();
        }

        $permissions = is_array($permissions) ? $permissions : [$permissions];

        return array_map(function ($permission) use ($context) {
            if ($permission instanceof Permission) {
                return $permission;
            }

            return $this->getPermissionClass()->findByNameFor($context, $permission, $this->getDefaultGuardName());
        }, $permissions);
    }

    /**
     * Determine if the model may globally perform the given permission.
     *
     * @param string|int|\Spatie\Permission\Contracts\Permission $permission
     * @param string|null $guardName
     *
     * @return bool
     * @throws PermissionDoesNotExist
     */
    public function hasPermissionTo($permission, $guardName = null): bool
    {
        return $this->hasPermissionFor(null, $permission, $guardName);
    }

    /**
     * Determine if the model may perform the given permission for a given context.
     *
     * @param null|Model $context
     * @param string|int|\Spatie\Permission\Contracts\Permission $permission
     * @param string|null $guardName
     *
     * @return bool
     * @throws PermissionDoesNotExist
     */
    public function hasPermissionFor(?Model $context, $permission, $guardName = null): bool
    {
        if (config('permission.enable_wildcard_permission', false)) {
            return $this->hasWildcardPermissionFor($context, $permission, $guardName);
        }

        $permissionClass = $this->getPermissionClass();

        if (is_string($permission)) {
            $permission = $permissionClass->findByNameFor($context, 
                $permission,
                $guardName ?? $this->getDefaultGuardName()
            );
        }

        if (is_int($permission)) {
            $permission = $permissionClass->findByIdFor($context, 
                $permission,
                $guardName ?? $this->getDefaultGuardName()
            );
        }

        if (! $permission instanceof Permission) {
            throw new PermissionDoesNotExist;
        }

        return $this->hasDirectPermissionFor($context, $permission) || $this->hasPermissionViaRoleFor($context, $permission);
    }

    /**
     * Validates a wildcard permission against all global permissions of a user.
     *
     * @param string|int|\Spatie\Permission\Contracts\Permission $permission
     * @param string|null $guardName
     *
     * @return bool
     */
    protected function hasWildcardPermission($permission, $guardName = null): bool
    {
        return $this->hasWildcardPermissionFor(null, $permission, $guardName);
    }

    /**
     * Validates a wildcard permission against all permissions of a user for a given context.
     *
     * @param null|Model $context
     * @param string|int|\Spatie\Permission\Contracts\Permission $permission
     * @param string|null $guardName
     *
     * @return bool
     */
    protected function hasWildcardPermissionFor(?Model $context, $permission, $guardName = null): bool
    {
        $guardName = $guardName ?? $this->getDefaultGuardName();

        if (is_int($permission)) {
            $permission = $this->getPermissionClass()->findByIdFor($context, $permission, $guardName);
        }

        if ($permission instanceof Permission) {
            $permission = $permission->name;
        }

        if (! is_string($permission)) {
            throw WildcardPermissionInvalidArgument::create();
        }

        foreach ($this->getAllPermissionsFor($context) as $userPermission) {
            if ($guardName !== $userPermission->guard_name) {
                continue;
            }

            $userPermission = new WildcardPermission($userPermission->name);

            if ($userPermission->implies($permission)) {
                return true;
            }
        }

        return false;
    }

    /**
     * @deprecated since 2.35.0
     * @alias of hasPermissionTo()
     */
    public function hasUncachedPermissionTo($permission, $guardName = null): bool
    {
        return $this->hasPermissionTo($permission, $guardName);
    }

    /**
     * @deprecated since 2.35.0
     * @alias of hasPermissionFor()
     */
    public function hasUncachedPermissionFor(?Model $context, $permission, $guardName = null): bool
    {
        return $this->hasPermissionFor($context, $permission, $guardName);
    }

    /**
     * An alias to hasPermission(), but avoids throwing an exception.
     *
     * @param string|int|\Spatie\Permission\Contracts\Permission $permission
     * @param string|null $guardName
     *
     * @return bool
     */
    public function checkPermissionTo($permission, $guardName = null): bool
    {
        return $this->checkPermissionFor(null, $permission, $guardName);
    }

    /**
     * An alias to hasPermissionFor(), but avoids throwing an exception.
     *
     * @param null|Model $context
     * @param string|int|\Spatie\Permission\Contracts\Permission $permission
     * @param string|null $guardName
     *
     * @return bool
     */
    public function checkPermissionFor(?Model $context, $permission, $guardName = null): bool
    {
        try {
            return $this->hasPermissionFor($context, $permission, $guardName);
        } catch (PermissionDoesNotExist $e) {
            return false;
        }
    }

    /**
     * Determine if the model has any of the given global permissions
     *
     * @param array ...$permissions
     *
     * @return bool
     * @throws \Exception
     */
    public function hasAnyPermission(...$permissions): bool
    {
        return $this->hasAnyPermissionFor(null, $permissions);
    }

    /**
     * Determine if the model has any of the given permissions for the given context.
     *
     * @param null|Model $context
     * @param array ...$permissions
     *
     * @return bool
     * @throws \Exception
     */
    public function hasAnyPermissionFor(?Model $context, ...$permissions): bool
    {
        $permissions = collect($permissions)->flatten();

        foreach ($permissions as $permission) {
            if ($this->checkPermissionFor($context, $permission)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Determine if the model has all of the given global permissions.
     *
     * @param array ...$permissions
     *
     * @return bool
     * @throws \Exception
     */
    public function hasAllPermissions(...$permissions): bool
    {
        return $this->hasAllPermissionsFor(null, $permissions);
    }

    /**
     * Determine if the model has all of the given permissions for the given context.
     *
     * @param null|Model $context
     * @param array ...$permissions
     *
     * @return bool
     * @throws \Exception
     */
    public function hasAllPermissionsFor(?Model $context, ...$permissions): bool
    {
        $permissions = collect($permissions)->flatten();

        foreach ($permissions as $permission) {
            if (! $this->hasPermissionFor($context, $permission)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Determine if the model has, via roles, the given global permission
     *
     * @param \Spatie\Permission\Contracts\Permission $permission
     *
     * @return bool
     */
    protected function hasPermissionViaRole(Permission $permission): bool
    {
        return $this->hasRoleFor(null, $permission->rolesFor(null)->get());
    }

    /**
     * Determine if the model has, via roles, the given permission for the given context.
     *
     * @param null|Model $context
     * @param \Spatie\Permission\Contracts\Permission $permission
     *
     * @return bool
     */
    protected function hasPermissionViaRoleFor(?Model $context, Permission $permission): bool
    {
        return $this->hasRoleFor($context, $permission->rolesFor($context)->get());
    }

    /**
     * Determine if the model has the given global permission.
     *
     * @param string|int|\Spatie\Permission\Contracts\Permission $permission
     *
     * @return bool
     * @throws PermissionDoesNotExist
     */
    public function hasDirectPermission($permission): bool
    {
        return $this->hasDirectPermissionFor(null, $permission);
    }

    /**
     * Determine if the model has the given permission for the given context.
     *
     * @param null|Model $context
     * @param string|int|\Spatie\Permission\Contracts\Permission $permission
     *
     * @return bool
     * @throws PermissionDoesNotExist
     */
    public function hasDirectPermissionFor(?Model $context, $permission): bool
    {
        $permissionClass = $this->getPermissionClass();

        if (is_string($permission)) {
            $permission = $permissionClass->findByNameFor($context, $permission, $this->getDefaultGuardName());
        }

        if (is_int($permission)) {
            $permission = $permissionClass->findByIdFor($context, $permission, $this->getDefaultGuardName());
        }

        if (! $permission instanceof Permission) {
            throw new PermissionDoesNotExist;
        }

        return $this->permissionsFor($context)->get()->contains('id', $permission->id);
    }

    /**
     * Return all the permissions the model has via roles.
     */
    public function getPermissionsViaRoles(): Collection
    {
        return $this->getPermissionsViaRolesFor(null);
    }

    /**
     * Return all the permissions the model has via roles for the given context.
     * 
     * @param null|Model $context
     */
    public function getPermissionsViaRolesFor(?Model $context) : Collection
    {
        return $this->loadMissing('roles', 'roles.permissions')
            ->rolesFor($context)->get()->flatMap(function ($role) {
                return $role->permissions;
            })->sort()->values();
    }

    /**
     * Return all the global permissions the model has, both directly and via roles.
     */
    public function getAllPermissions(): Collection
    {
        return $this->getAllPermissionsFor(null);
    }

    /**
     * Return all the permissions the model has, both directly and via roles for a given context.
     * 
     * @param null|Model $context
     */
    public function getAllPermissionsFor(?Model $context): Collection
    {
        /** @var Collection $permissions */
        $permissions = $this->permissionsFor($context)->get();

        if ($this->usesRoles) {
            $permissions = $permissions->merge($this->getPermissionsViaRolesFor($context));
        }

        return $permissions->sort()->values();
    }

    /**
     * Grant global permission(s) to a model.
     *
     * @param string|array|\Spatie\Permission\Contracts\Permission|\Illuminate\Support\Collection $permissions
     *
     * @return $this
     */
    public function givePermissionTo(...$permissions)
    {
        $this->givePermissionFor(null, $permissions);

        return $this;
    }

    /**
     * Grant permission(s) for a context to a model.
     *
     * @param null|Model $context
     * @param string|array|\Spatie\Permission\Contracts\Permission|\Illuminate\Support\Collection $permissions
     *
     * @return $this
     */
    public function givePermissionFor(?Model $context, ...$permissions)
    {
        $permissions = collect($permissions)
            ->flatten()
            ->map(function ($permission) use ($context) {
                if (empty($permission)) {
                    return false;
                }

                return $this->getStoredPermissionFor($context, $permission);
            })
            ->filter(function ($permission) {
                return $permission instanceof Permission;
            })
            ->each(function ($permission) {
                $this->ensureModelSharesGuard($permission);
            });

        $model = $this->getModel();

        if ($model->exists) {
            $this->attachPermissionsFor($context, $permissions);
            $model->load('permissions');
        } else {
            $class = \get_class($model);

            $class::saved(
                function ($object) use ($permissions, $model, $context) {
                    static $modelLastFiredOn;
                    if ($modelLastFiredOn !== null && $modelLastFiredOn === $model) {
                        return;
                    }
                    $object->attachPermissionsFor($context, $permissions);
                    $object->load('permissions');
                    $modelLastFiredOn = $object;
                }
            );
        }

        $this->forgetCachedPermissions();

        return $this;
    }

    /**
     * Attach Permissions to the model for the given context
     *
     * @param Model|null $context
     * @param int[]|string[]|\Illuminate\Support\Collection|\Spatie\Permission\Contracts\Permission[] $permissions
     * @return $this
     */
    public function attachPermissionsFor(?Model $context, $permissions)
    {
        $modelType = static::class;
        $morphKey = config('permission.column_names.model_morph_key');

        foreach ($permissions as $permission) {
            $permission = $this->getStoredPermissionFor($context, $permission);

            if (! $this->permissionsFor($context)->where('id', $permission->id)->exists()) {
                $permission->attachFor($context, [
                    'model_type' => $modelType,
                    $morphKey => $this->id,
                ]);
            }
        }

        return $this;
    }

    /**
     * Remove all current global permissions and set the given ones.
     *
     * @param string|array|\Spatie\Permission\Contracts\Permission|\Illuminate\Support\Collection $permissions
     *
     * @return $this
     */
    public function syncPermissions(...$permissions)
    {
        $this->syncPermissionsFor(null, $permissions);

        return $this;
    }

    /**
     * Remove all current permissions and set the given ones.
     *
     * @param string|array|\Spatie\Permission\Contracts\Permission|\Illuminate\Support\Collection $permissions
     *
     * @return $this
     */
    public function syncPermissionsFor(?Model $context, ...$permissions)
    {
        $this->permissionsFor($context)->detach();

        return $this->givePermissionFor($context, $permissions);
    }

    /**
     * Revoke the given global permission
     *
     * @param \Spatie\Permission\Contracts\Permission|\Spatie\Permission\Contracts\Permission[]|string|string[] $permission
     *
     * @return $this
     */
    public function revokePermissionTo($permission)
    {
        $this->revokePermissionFor(null, $permission);

        return $this;
    }

    /**
     * Revoke the given permission for the given context.
     *
     * @param null|Model $context
     * @param \Spatie\Permission\Contracts\Permission|\Spatie\Permission\Contracts\Permission[]|string|string[] $permission
     *
     * @return $this
     */
    public function revokePermissionFor(?Model $context, $permission)
    {
        $this->permissionsFor($context)->detach($this->getStoredPermissionFor($context, $permission));

        $this->forgetCachedPermissions();

        $this->load('permissions');

        return $this;
    }

    /**
     * Revoke all permissions from the model for the every context.
     *
     * @return $this
     */
    public function removeAllPermissions()
    {
        $this->permissions()->detach();

        $this->load('permissions');

        $this->forgetCachedPermissions();

        return $this;
    }

    /**
     * Revoke all permissions from the model for the global context.
     *
     * @return $this
     */
    public function revokeAllGlobalPermissions()
    {
        $this->permissionsFor(null)->detach();

        $this->load('permissions');

        $this->forgetCachedPermissions();

        return $this;
    }

    /**
     * Revoke all permissions from the model for the given context.
     *
     * @param Model $context
     *
     * @return $this
     */
    public function revokeAllPermissionsFor(Model $context)
    {
        $this->permissionsFor($context)->detach();

        $this->load('permissions');

        $this->forgetCachedPermissions();

        return $this;
    }

    /**
     * Get the names of the model's global permissions
     *
     * @return Collection
     */
    public function getPermissionNames(): Collection
    {
        return $this->getPermissionNamesFor(null);
    }

    /**
     * Get the names of the model's permissions for the given context
     *
     * @param Model|null $context
     * @return Collection
     */
    public function getPermissionNamesFor(?Model $context): Collection
    {
        return $this->permissionsFor($context)->get()->pluck('name');
    }

    /**
     * @param string|array|\Spatie\Permission\Contracts\Permission|\Illuminate\Support\Collection $permissions
     *
     * @return \Spatie\Permission\Contracts\Permission|\Spatie\Permission\Contracts\Permission[]|\Illuminate\Support\Collection
     */
    protected function getStoredPermission($permissions)
    {
        return $this->getStoredPermissionFor(null, $permissions);
    }

    /**
     * @param null|Model $context
     * @param string|array|\Spatie\Permission\Contracts\Permission|\Illuminate\Support\Collection $permissions
     *
     * @return \Spatie\Permission\Contracts\Permission|\Spatie\Permission\Contracts\Permission[]|\Illuminate\Support\Collection
     */
    protected function getStoredPermissionFor(?Model $context, $permissions)
    {
        $permissionClass = $this->getPermissionClass();

        if (is_numeric($permissions)) {
            return $permissionClass->findByIdFor($context, $permissions, $this->getDefaultGuardName());
        }

        if (is_string($permissions)) {
            return $permissionClass->findByNameFor($context, $permissions, $this->getDefaultGuardName());
        }

        if (is_array($permissions)) {
            return $permissionClass
                ->whereIn('name', $permissions)
                ->whereIn('guard_name', $this->getGuardNames())
                ->get();
        }

        return $permissions;
    }

    /**
     * @param \Spatie\Permission\Contracts\Permission|\Spatie\Permission\Contracts\Role $roleOrPermission
     *
     * @throws \Spatie\Permission\Exceptions\GuardDoesNotMatch
     */
    protected function ensureModelSharesGuard($roleOrPermission)
    {
        if (! $this->getGuardNames()->contains($roleOrPermission->guard_name)) {
            throw GuardDoesNotMatch::create($roleOrPermission->guard_name, $this->getGuardNames());
        }
    }

    protected function getGuardNames(): Collection
    {
        return Guard::getNames($this);
    }

    protected function getDefaultGuardName(): string
    {
        return Guard::getDefaultName($this);
    }

    /**
     * Forget the cached permissions.
     */
    public function forgetCachedPermissions()
    {
        app(PermissionRegistrar::class)->forgetCachedPermissions();
    }

    /**
     * Check if the model has All of the requested Direct permissions.
     *
     * @param array ...$permissions
     * @return bool
     */
    public function hasAllDirectPermissions(...$permissions): bool
    {
        return $this->hasallDirectPermissionsFor(null, $permissions);
    }

    /**
     * Check if the model has All of the requested Direct permissions.
     *
     * @param null|Model $context
     * @param array ...$permissions
     * @return bool
     */
    public function hasAllDirectPermissionsFor(?Model $context, ...$permissions): bool
    {
        $permissions = collect($permissions)->flatten();

        foreach ($permissions as $permission) {
            if (! $this->hasDirectPermissionFor($context, $permission)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Check if the model has Any of the requested Direct global permissions.
     * 
     * @param array ...$permissions
     * @return bool
     */
    public function hasAnyDirectPermission(...$permissions): bool
    {
        return $this->hasAnyDirectPermissionFor(null, $permissions);
    }

    /**
     * Check if the model has Any of the requested Direct permissions for the given context.
     * 
     * @param null|Model $context
     * @param array ...$permissions
     * @return bool
     */
    public function hasAnyDirectPermissionFor(?Model $context, ...$permissions): bool
    {
        $permissions = collect($permissions)->flatten();

        foreach ($permissions as $permission) {
            if ($this->hasDirectPermissionFor($context, $permission)) {
                return true;
            }
        }

        return false;
    }
}
