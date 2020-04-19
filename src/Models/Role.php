<?php

namespace Spatie\Permission\Models;

use Spatie\Permission\Guard;
use Illuminate\Database\Eloquent\Model;
use Spatie\Permission\Traits\HasPermissions;
use Spatie\Permission\Exceptions\RoleDoesNotExist;
use Spatie\Permission\Exceptions\GuardDoesNotMatch;
use Spatie\Permission\Exceptions\RoleAlreadyExists;
use Spatie\Permission\Contracts\Role as RoleContract;
use Spatie\Permission\Traits\RefreshesPermissionCache;
use Illuminate\Database\Eloquent\Relations\MorphToMany;
use Illuminate\Database\Eloquent\Relations\BelongsToMany;
use Illuminate\Support\Facades\DB;

class Role extends Model implements RoleContract
{
    use HasPermissions;
    use RefreshesPermissionCache;

    protected $guarded = ['id'];

    public function __construct(array $attributes = [])
    {
        $attributes['guard_name'] = $attributes['guard_name'] ?? config('auth.defaults.guard');

        parent::__construct($attributes);

        $this->setTable(config('permission.table_names.roles'));
    }

    public static function create(array $attributes = [])
    {
        $attributes['guard_name'] = $attributes['guard_name'] ?? Guard::getDefaultName(static::class);
        $attributes['context_type'] = $attributes['context_type'] ?? 'global';

        if (static::where('name', $attributes['name'])->where('guard_name', $attributes['guard_name'])->where('context_type', $attributes['context_type'])->first()) {
            throw RoleAlreadyExists::create($attributes['name'], $attributes['guard_name'], $attributes['context_type']);
        }

        return static::query()->create($attributes);
    }

    /**
     * Get all the permissions associated with the role for all contexts
     *
     * @return BelongsToMany
     */
    public function permissions() : BelongsToMany
    {
        return $this->belongsToMany(
            config('permission.models.permission'),
            config('permission.table_names.role_has_permissions'),
            'role_id',
            'permission_id'
        );
    }

    /**
     * Get the global permissions associated with the role
     */
    public function globalPermissions(): BelongsToMany
    {
        return $this->permissions();
    }

    /**
     * @param null|Model $context
     * 
     * A role may be given various permissions.
     */
    public function permissionsFor(?Model $context): BelongsToMany
    {
        return $this->permissions();
    }

    /**
     * Get all users associated with the role for all contexts
     *
     * @return MorphToMany
     */
    public function users() : MorphToMany
    {
        return $this->morphedByMany(
            getModelForGuard($this->attributes['guard_name']),
            'model',
            config('permission.table_names.model_has_roles'),
            'role_id',
            config('permission.column_names.model_morph_key')
        )->withPivot([
            'context_type',
            'context_id'
        ]);
    }

    /**
     * @param null|Model $context
     * A role belongs to some users of the model associated with its guard.
     */
    public function usersFor(?Model $context): MorphToMany
    {
        if ($context === null) {
            return $this->users()
                        ->wherePivot('context_type', 'global')
                        ->wherePivot('context_id', 0)
                        ->withPivot([
                            'context_type',
                            'context_id'
                        ]);
        }

        $contextType = (new \ReflectionClass($context))->getName();

        return $this->users()
                    ->wherePivot('context_type', $contextType)
                    ->wherePivot('context_id', $context->id)
                    ->withPivot([
                        'context_type',
                        'context_id'
                    ]);
    }

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
    public static function findByName(string $name, $guardName = null): RoleContract
    {
        return self::findByNameFor(null, $name, $guardName);
    }

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
    public static function findByNameFor(?Model $context, string $name, $guardName = null): RoleContract
    {
        $guardName = $guardName ?? Guard::getDefaultName(static::class);

        if ($context === null) {
            $contextType = 'global';
        } else {
            $contextType = (new \ReflectionClass($context))->getName();
        }

        $role = static::where('name', $name)->where('guard_name', $guardName)->where('context_type', $contextType)->first();

        if (! $role) {
            throw RoleDoesNotExist::named($name, $context);
        }

        return $role;
    }

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
    public static function findById(int $id, $guardName = null): RoleContract
    {
        return self::findByIdFor(null, $id, $guardName);
    }

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
    public static function findByIdFor(?Model $context, int $id, $guardName = null): RoleContract
    {
        $guardName = $guardName ?? Guard::getDefaultName(static::class);

        if ($context === null) {
            $contextType = 'global';
        } else {
            $contextType = (new \ReflectionClass($context))->getName();
        }

        $role = static::where('id', $id)->where('guard_name', $guardName)->first();

        if (! $role) {
            throw RoleDoesNotExist::withId($id, $contextType);
        }

        return $role;
    }

    /**
     * Find or create a global role by its name (and optionally guardName).
     *
     * @param string $name
     * @param string|null $guardName
     *
     * @return \Spatie\Permission\Contracts\Role
     */
    public static function findOrCreate(string $name, $guardName = null): RoleContract
    {
        return self::findOrCreateFor(null, $name, $guardName);
    }

    /**
     * Find or create role by its name (and optionally guardName) for the given context.
     *
     * @param null|Model $context
     * @param string $name
     * @param string|null $guardName
     *
     * @return \Spatie\Permission\Contracts\Role
     */
    public static function findOrCreateFor(?Model $context, string $name, $guardName = null): RoleContract
    {
        $guardName = $guardName ?? Guard::getDefaultName(static::class);

        if ($context === null) {
            $contextType = 'global';
        } else {
            $contextType = (new \ReflectionClass($context))->getName();
        }

        $role = static::where('name', $name)->where('guard_name', $guardName)->where('context_type', $contextType)->first();

        if (! $role) {
            return static::query()->create(['name' => $name, 'guard_name' => $guardName, 'context_type'=> $contextType]);
        }

        return $role;
    }

    /**
     * Determine if the user may perform the given permission.
     *
     * @param string|Permission $permission
     *
     * @return bool
     *
     * @throws \Spatie\Permission\Exceptions\GuardDoesNotMatch
     */
    public function hasPermissionTo($permission): bool
    {
        return $this->hasPermissionFor(null, $permission);
    }

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
    public function hasPermissionFor(?Model $context, $permission): bool
    {
        if (config('permission.enable_wildcard_permission', false)) {
            return $this->hasWildcardPermissionFor($context, $permission, $this->getDefaultGuardName());
        }

        $permissionClass = $this->getPermissionClass();

        if (is_string($permission)) {
            $permission = $permissionClass->findByNameFor($context, $permission, $this->getDefaultGuardName());
        }

        if (is_int($permission)) {
            $permission = $permissionClass->findByIdFor($context, $permission, $this->getDefaultGuardName());
        }

        if (! $this->getGuardNames()->contains($permission->guard_name)) {
            throw GuardDoesNotMatch::create($permission->guard_name, $this->getGuardNames());
        }

        return $this->permissions->contains('id', $permission->id);
    }

    /**
     * Attach a related model to the role for a given context
     *
     * @param Model|null $context
     * @param array $attributes
     * @return void
     */
    public function attachFor(?Model $context, array $attributes = [])
    {
        if ($attributes['model_type'] === config('permission.models.permission')) {
            $morphKey = config('permission.column_names.model_morph_key');
            $this->permissions()->attach($attributes[$morphKey]);
        }

        if ($context !== null) {
            $contextType = (new \ReflectionClass($context))->getName();
            $contextId = $context->id;
        } else {
            $contextType = 'global';
            $contextId = 0;
        }

        $attributes['role_id'] = $this->id;
        $attributes['context_type'] = $contextType;
        $attributes['context_id'] = $contextId;

        DB::table(config('permission.table_names.model_has_roles'))
            ->insert($attributes);
    }
}
