<?php

namespace Spatie\Permission\Contracts;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsToMany;

interface Role
{
    /**
     * Get all the permissions associated with the role for all contexts
     *
     * @return BelongsToMany
     */
    public function permissions() : BelongsToMany;
    
    /**
     * Get the global permissions associated with the role
     */
    public function globalPermissions(): BelongsToMany;
    
    /**
     * @param null|Model $context
     * 
     * A role may be given various permissions.
     */
    public function permissionsFor(?Model $context): BelongsToMany;
    
    /**
     * Find a global role by its name and guard name.
     *
     * @param string $name
     * @param string|null $guardName
     *
     * @return \Spatie\Permission\Contracts\Role|\Spatie\Permission\Models\Role
     *
     * @throws \Spatie\Permission\Exceptions\RoleDoesNotExist
     */
    public static function findByName(string $name, $guardName = null): self;
    
    /**
     * Find a role by its name, guard name and context.
     *
     * @param null|Model $context
     * @param string $name
     * @param string|null $guardName
     *
     * @return \Spatie\Permission\Contracts\Role|\Spatie\Permission\Models\Role
     *
     * @throws \Spatie\Permission\Exceptions\RoleDoesNotExist
     */
    public static function findByNameFor(?Model $context, string $name, $guardName = null): self;
    
    /**
     * Find a global role by its id, guard name.
     *
     * @param int $id
     * @param string|null $guardName
     *
     * @return \Spatie\Permission\Contracts\Role|\Spatie\Permission\Models\Role
     *
     * @throws \Spatie\Permission\Exceptions\RoleDoesNotExist
     */
    public static function findById(int $id, $guardName = null): self;
    
    /**
     * Find a role by its id, guard name and context.
     *
     * @param null|Model $context
     * @param int $id
     * @param string|null $guardName
     *
     * @return \Spatie\Permission\Contracts\Role|\Spatie\Permission\Models\Role
     *
     * @throws \Spatie\Permission\Exceptions\RoleDoesNotExist
     */
    public static function findByIdFor(?Model $context, int $id, $guardName = null): self;
    
    /**
     * Find or create a global role by its name (and optionally guardName).
     *
     * @param string $name
     * @param string|null $guardName
     *
     * @return \Spatie\Permission\Contracts\Role
     */
    public static function findOrCreate(string $name, $guardName = null): self;
    
    /**
     * Find or create role by its name (and optionally guardName) for the given context.
     *
     * @param null|Model $context
     * @param string $name
     * @param string|null $guardName
     *
     * @return \Spatie\Permission\Contracts\Role
     */
    public static function findOrCreateFor(?Model $context, string $name, $guardName = null): self;
    
    /**
     * Determine if the user may perform the given permission.
     *
     * @param string|Permission $permission
     *
     * @return bool
     *
     * @throws \Spatie\Permission\Exceptions\GuardDoesNotMatch
     */
    public function hasPermissionTo($permission): bool;
    
    /**
     * Determine if the user may perform the given permission.
     *
     * @param null|Model $context
     * @param string|Permission $permission
     *
     * @return bool
     *
     * @throws \Spatie\Permission\Exceptions\GuardDoesNotMatch
     */
    public function hasPermissionFor(?Model $context, $permission): bool;
    
    /**
     * Attach a related model to the role for a given context
     *
     * @param Model|null $context
     * @param array $attributes
     * @return void
     */
    public function attachFor(?Model $context, array $attributes = []);
}
