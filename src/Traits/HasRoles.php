<?php

namespace Spatie\Permission\Traits;

use Illuminate\Support\Collection;
use Spatie\Permission\Contracts\Role;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Spatie\Permission\PermissionRegistrar;
use Illuminate\Database\Eloquent\Relations\MorphToMany;

trait HasRoles
{
    use HasPermissions;

    private $roleClass;
    private $usesRoles = true;

    public static function bootHasRoles()
    {
        static::deleting(function ($model) {
            if (method_exists($model, 'isForceDeleting') && ! $model->isForceDeleting()) {
                return;
            }

            $model->roles()->detach();
        });
    }

    public function getRoleClass()
    {
        if (! isset($this->roleClass)) {
            $this->roleClass = app(PermissionRegistrar::class)->getRoleClass();
        }

        return $this->roleClass;
    }

    /**
     * The model's roles for every context.
     */
    public function roles(): MorphToMany
    {
        return $this->morphToMany(
            config('permission.models.role'),
            'model',
            config('permission.table_names.model_has_roles'),
            config('permission.column_names.model_morph_key'),
            'role_id'
        )
        ->withPivot([
            'context_type',
            'context_id'
        ]);
    }


    /**
     * The model's global roles
     */
    public function globalRoles() : MorphToMany
    {
        return $this->rolesFor(null);    
    }

    /**
     * The model's roles for a context.
     */
    public function rolesFor(?Model $context) : MorphToMany
    {
        if ($context === null) {
            return $this->roles()
                        ->wherePivot('context_type', 'global')
                        ->wherePivot('context_id', 0)
                        ->withPivot([
                            'context_type',
                            'context_id'
                        ]);
        }

        $contextType = (new \ReflectionClass($context))->getName();

        return $this->roles()
                    ->wherePivot('context_type', $contextType)
                    ->wherePivot('context_id', $context->id)
                    ->withPivot([
                        'context_type',
                        'context_id'
                    ]);
    }

    /**
     * Scope the model query to certain roles only.
     *
     * @param \Illuminate\Database\Eloquent\Builder $query
     * @param string|array|\Spatie\Permission\Contracts\Role|\Illuminate\Support\Collection $roles
     * @param string $guard
     *
     * @return \Illuminate\Database\Eloquent\Builder
     */
    public function scopeRole(Builder $query, $roles, $guard = null): Builder
    {
        return $this->scopeRoleFor(null, $query, $roles, $guard);
    }

    /**
     * Scope the model query to certain roles only.
     *
     * @param null|Model $context
     * @param \Illuminate\Database\Eloquent\Builder $query
     * @param string|array|\Spatie\Permission\Contracts\Role|\Illuminate\Support\Collection $roles
     * @param string $guard
     *
     * @return \Illuminate\Database\Eloquent\Builder
     */
    public function scopeRoleFor(?Model $context, Builder $query, $roles, $guard = null): Builder
    {
        if ($context === null) {
            $contextType = 'global';
        } else {
            $contextType = (new \ReflectionClass($context))->getName();
        }
        
        if ($roles instanceof Collection) {
            $roles = $roles->all();
        }

        if (! is_array($roles)) {
            $roles = [$roles];
        }

        $roles = array_map(function ($role) use ($guard) {
            if ($role instanceof Role) {
                return $role;
            }

            $method = is_numeric($role) ? 'findById' : 'findByName';
            $guard = $guard ?: $this->getDefaultGuardName();

            return $this->getRoleClass()->{$method}($role, $guard);
        }, $roles);

        return $query->whereHas('roles', function (Builder $subQuery) use ($roles, $contextType) {
            $subQuery->whereIn(config('permission.table_names.roles').'.id', \array_column($roles, 'id'))
                     ->where(config('permission.table_names.roles').'.context_type', $contextType);
        });
    }

    /**
     * Assign global role(s) to the model
     *
     * @param array|string|\Spatie\Permission\Models\Role|\Spatie\Permission\Contracts\Role|\Illuminate\Support\Collection ...$roles
     * @return $this
     */
    public function assignRole(...$roles)
    {
        $this->assignRoleFor(null, $roles);
        
        return $this;
    }

    /**
     * Assign role(s) to the user for a given context
     *
     * @param null|Model $context
     * @param array|string|\Spatie\Permission\Models\Role|\Spatie\Permission\Contracts\Role|\Illuminate\Support\Collection ...$roles
     * @return $this
     */
    public function assignRoleFor(?Model $context, ...$roles)
    {
        $roles = collect($roles)
            ->flatten()
            ->map(function ($role) use ($context) {
                if (empty($role)) {
                    return false;
                }

                return $this->getStoredRoleFor($context, $role);
            })
            ->filter(function ($role) {
                return $role instanceof Role;
            })
            ->each(function ($role) {
                $this->ensureModelSharesGuard($role);
            })
            ->all();

        $model = $this->getModel();

        if ($model->exists) {
            $this->attachRolesFor($context, $roles);
            $model->load('roles');
        } else {
            $class = \get_class($model);

            $class::saved(
                function ($object) use ($roles, $model, $context) {
                    static $modelLastFiredOn;
                    if ($modelLastFiredOn !== null && $modelLastFiredOn === $model) {
                        return;
                    }
                    $object->attachRolesFor($context, $roles);
                    $object->load('roles');
                    $modelLastFiredOn = $object;
                });
        }

        $this->forgetCachedPermissions();

        return $this;
    }

    /**
     * Revoke the given global role from the model.
     *
     * @param string|\Spatie\Permission\Contracts\Role $role
     * @return $this
     */
    public function removeRole($role)
    {
        $this->removeRoleFor(null, $role);

        return $this;
    }

    /**
     * Revoke the given contextual role from the model.
     *
     * @param null|Model $context
     * @param string|\Spatie\Permission\Contracts\Role $role
     * @return $this
     */
    public function removeRoleFor(?Model $context, $role)
    {
        $this->rolesFor($context)->detach($this->getStoredRoleFor($context, $role));

        $this->load('roles');

        $this->forgetCachedPermissions();

        return $this;
    }

    /**
     * Revoke all roles from the model for the every context.
     *
     * @return $this
     */
    public function removeAllRoles()
    {
        $this->roles()->detach();

        $this->load('roles');

        $this->forgetCachedPermissions();

        return $this;
    }

    /**
     * Revoke all roles from the model for the global context.
     *
     * @return $this
     */
    public function removeAllGlobalRoles()
    {
        $this->rolesFor(null)->detach();

        $this->load('roles');

        $this->forgetCachedPermissions();

        return $this;
    }

    /**
     * Revoke all roles from the model for the given context.
     *
     * @param Model $context
     *
     * @return $this
     */
    public function removeAllRolesFor(Model $context)
    {
        $this->rolesFor($context)->detach();

        $this->load('roles');

        $this->forgetCachedPermissions();

        return $this;
    }

    /**
     * Remove all current global roles and set the given ones.
     *
     * @param array|\Spatie\Permission\Contracts\Role|string  ...$roles
     *
     * @return $this
     */
    public function syncRoles(...$roles)
    {
        $this->syncRolesFor(null, $roles);
    }

    /**
     * Remove all current roles for a context and set the given ones.
     *
     * @param null|Model $context
     * @param array|\Spatie\Permission\Contracts\Role|string  ...$roles
     *
     * @return $this
     */
    public function syncRolesFor(?Model $context, ...$roles)
    {
        $this->rolesFor($context)->detach();

        return $this->assignRoleFor($context, $roles);
    }

    /**
     * Attach Roles to the model for the given context
     *
     * @param Model|null $context
     * @param int[]|string[]|\Illuminate\Support\Collection|\Spatie\Permission\Contracts\Role[] $roles
     * @return $this
     */
    public function attachRolesFor(?Model $context, array $roles)
    {
        $modelType = static::class;
        $morphKey = config('permission.column_names.model_morph_key');

        foreach ($roles as $role) {
            $role = $this->getStoredRoleFor($context, $role);
            
            if (! $this->rolesFor($context)->where('id', $role->id)->exists()) {
                    $role->attachFor($context, [
                        'model_type' => $modelType,
                        $morphKey => $this->id,
                    ]);
            }
        }

        return $this;
    }

    /**
     * Determine if the model has (one of) the given global role(s).
     * 
     * @param string|int|array|\Spatie\Permission\Contracts\Role|\Illuminate\Support\Collection $roles
     * @param string|null $guard
     * @return bool
     */
    public function hasRole($roles, string $guard = null): bool
    {
        return $this->hasRoleFor(null, $roles, $guard);
    }

    /**
     * Determine if the model has (one of) the given role(s) in the given context.
     * 
     * @param null|Model $context
     * @param string|int|array|\Spatie\Permission\Contracts\Role|\Illuminate\Support\Collection $roles
     * @param string|null $guard
     * @return bool
     */
    public function hasRoleFor(?Model $context, $roles, string $guard = null): bool
    {
        if (is_string($roles) && false !== strpos($roles, '|')) {
            $roles = $this->convertPipeToArray($roles);
        }

        if (is_string($roles)) {
            return $guard
                ? $this->rolesFor($context)->get()
                    ->where('guard_name', $guard)->contains('name', $roles)
                : $this->rolesFor($context)->get()->contains('name', $roles);
        }

        if (is_int($roles)) {
            return $guard
                ? $this->rolesFor($context)->get()
                    ->where('guard_name', $guard)->contains('id', $roles)
                : $this->rolesFor($context)->get()->contains('id', $roles);
        }

        if ($roles instanceof Role) {
            return $this->rolesFor($context)->get()->contains('id', $roles->id);
        }

        if (is_array($roles)) {
            foreach ($roles as $role) {
                if ($this->hasRoleFor($context, $role, $guard)) {
                    return true;
                }
            }

            return false;
        }

        return $roles->intersect($guard ? $this->rolesFor($context)->get()->where('guard_name', $guard) : $this->rolesFor($context)->get())->isNotEmpty();
    }

    /**
     * Determine if the model has any of the given global role(s)
     *
     * Alias to hasRole() but without Guard controls
     * 
     * @param string|int|array|\Spatie\Permission\Contracts\Role|\Illuminate\Support\Collection $roles
     *
     * @return bool
     */
    public function hasAnyRole(...$roles): bool
    {
        return $this->hasRole($roles);
    }

    /**
     * Determine if the model has any of the given role(s) given the context.
     *
     * Alias to hasRoleFor() but without Guard controls
     *
     * @param null|Model $context
     * @param string|int|array|\Spatie\Permission\Contracts\Role|\Illuminate\Support\Collection $roles
     *
     * @return bool
     */
    public function hasAnyRoleFor(?Model $context, ...$roles): bool
    {
        return $this->hasRoleFor($context, $roles);
    }

    /**
     * Determine if the model has all of the given global role(s).
     * 
     * @param  string|array|\Spatie\Permission\Contracts\Role|\Illuminate\Support\Collection  $roles
     * @param  string|null  $guard
     * @return bool
     */
    public function hasAllRoles($roles, string $guard = null): bool
    {
        return $this->hasAllRolesFor(null, $roles, $guard);
    }

    /**
     * Determine if the model has all of the given role(s) for a given context.
     * 
     * @param null|Model $context
     * @param  string|array|\Spatie\Permission\Contracts\Role|\Illuminate\Support\Collection  $roles
     * @param  string|null  $guard
     * @return bool
     */
    public function hasAllRolesFor(?Model $context, $roles, string $guard = null): bool
    {
        if (is_string($roles) && false !== strpos($roles, '|')) {
            $roles = $this->convertPipeToArray($roles);
        }

        if (is_string($roles)) {
            return $guard
                ? $this->rolesFor($context)->get()->where('guard_name', $guard)->contains('name', $roles)
                : $this->rolesFor($context)->get()->contains('name', $roles);
        }

        if ($roles instanceof Role) {
            return $this->rolesFor($context)->get()->contains('id', $roles->id);
        }

        $roles = collect()->make($roles)->map(function ($role) {
            return $role instanceof Role ? $role->name : $role;
        });

        return $roles->intersect(
            $guard
                ? $this->rolesFor($context)->get()->where('guard_name', $guard)->pluck('name')
                : $this->getRoleNamesFor($context)) == $roles;
    }

    /**
     * Return all permissions directly coupled to the model.
     */
    public function getDirectPermissions(): Collection
    {
        return $this->getDirectPermissionsFor(null);
    }

    /**
     * Return all permissions directly coupled to the model given the context.
     * 
     * @param null|Model $context
     */
    public function getDirectPermissionsFor(?Model $context): Collection
    {
        return $this->permissionsFor($context)->get();
    }

    /**
     * Get the names of the global roles the model has
     *
     * @return Collection
     */
    public function getRoleNames(): Collection
    {
        return $this->getRoleNamesFor(null);
    }

    /**
     * Get the names of the roles the model has for a given context
     *
     * @param Model|null $context
     * @return Collection
     */
    public function getRoleNamesFor(?Model $context): Collection
    {
        return $this->rolesFor($context)->get()->pluck('name');
    }

    /**
     * Get the names of all the global roles the model has
     *
     * @return Collection
     */
    public function getAllRoleNames(): Collection
    {
        return $this->rolesFor(null)->get()->pluck('name');
    }

    /**
     * Get the names of all the roles the model has in the given context
     *
     * @param null|Model $context
     * 
     * @return Collection
     */
    public function getAllRoleNamesFor(?Model $context): Collection
    {
        return $this->rolesFor($context)->get()->pluck('name');
    }

    /**
     * Resolve a role from the system to its contract
     *
     * @param string|array|\Spatie\Permission\Contracts\Role|\Illuminate\Support\Collection $role
     *
     * @return \Spatie\Permission\Contracts\Role|\Spatie\Permission\Contracts\Role[]|\Illuminate\Support\Collection
     */
    protected function getStoredRole($role)
    {
        return $this->getStoredRoleFor(null, $role);
    }

    /**
     * Resolve a role from the system to its contract
     *
     * @param string|array|\Spatie\Permission\Contracts\Role|\Illuminate\Support\Collection $role
     *
     * @return \Spatie\Permission\Contracts\Role|\Spatie\Permission\Contracts\Role[]|\Illuminate\Support\Collection
     */
    protected function getStoredRoleFor(?Model $context, $role)
    {
        $roleClass = $this->getRoleClass();

        if (is_numeric($role)) {
            return $roleClass->findByIdFor($context, $role, $this->getDefaultGuardName());
        }

        if (is_string($role)) {
            return $roleClass->findByNameFor($context, $role, $this->getDefaultGuardName());
        }

        return $role;
    }

    protected function convertPipeToArray(string $pipeString)
    {
        $pipeString = trim($pipeString);

        if (strlen($pipeString) <= 2) {
            return $pipeString;
        }

        $quoteCharacter = substr($pipeString, 0, 1);
        $endCharacter = substr($quoteCharacter, -1, 1);

        if ($quoteCharacter !== $endCharacter) {
            return explode('|', $pipeString);
        }

        if (! in_array($quoteCharacter, ["'", '"'])) {
            return explode('|', $pipeString);
        }

        return explode('|', trim($pipeString, $quoteCharacter));
    }
}
