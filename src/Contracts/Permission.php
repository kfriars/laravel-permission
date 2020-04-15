<?php

namespace Spatie\Permission\Contracts;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsToMany;

interface Permission
{
    /**
     * A permission can be applied to roles.
     */
    public function roles(): BelongsToMany;
    
    /**
     * Get the permission's global roles.
     * 
     * @return BelongsToMany
     */
    public function globalRoles(): BelongsToMany;
    
    /**
     * Get the permission's roles for the given context.
     * 
     * @param null|Model $context
     * 
     * @return BelongsToMany
     */
    public function rolesFor(?Model $context): BelongsToMany;
    
    /**
     * Find a global permission by its name (and optionally guardName).
     *
     * @param string $name
     * @param string|null $guardName
     *
     * @throws Spatie\Permission\Exceptions\PermissionDoesNotExist
     *
     * @return \Spatie\Permission\Contracts\Permission
     */
    public static function findByName(string $name, $guardName = null): self;
    
    /**
     * Find a permission by its name (and optionally guardName) for the given context.
     *
     * @param null|Model $context
     * @param string $name
     * @param string|null $guardName
     *
     * @throws Spatie\Permission\Exceptions\PermissionDoesNotExist
     *
     * @return \Spatie\Permission\Contracts\Permission
     */
    public static function findByNameFor(?Model $context, string $name, $guardName = null): self;
    
    /**
     * Find a global permission by its id (and optionally guardName).
     *
     * @param int $id
     * @param string|null $guardName
     *
     * @throws Spatie\Permission\Exceptions\PermissionDoesNotExist
     *
     * @return \Spatie\Permission\Contracts\Permission
     */
    public static function findById(int $id, $guardName = null): self;
    
    /**
     * Find a permission by its id (and optionally guardName) for the given context.
     *
     * @param null|Model $context
     * @param int $id
     * @param string|null $guardName
     *
     * @throws Spatie\Permission\Exceptions\PermissionDoesNotExist
     *
     * @return \Spatie\Permission\Contracts\Permission
     */
    public static function findByIdFor(?Model $context, int $id, $guardName = null): self;
    
    /**
     * Find or create a global permission by its name (and optionally guardName).
     *
     * @param string $name
     * @param string|null $guardName
     *
     * @return \Spatie\Permission\Contracts\Permission
     */
    public static function findOrCreate(string $name, $guardName = null): self;
    
    /**
     * Find or create permission by its name (and optionally guardName) for the given context.
     *
     * @param null|Model $context
     * @param string $name
     * @param string|null $guardName
     *
     * @return \Spatie\Permission\Contracts\Permission
     */
    public static function findOrCreateFor(?Model $context, string $name, $guardName = null): self;
    
    /**
     * Attach a related model to the permission for a given context
     *
     * @param Model|null $context
     * @param array $attributes
     * @return void
     */
    public function attachFor(?Model $context, array $attributes = []);
}
