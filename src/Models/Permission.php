<?php

namespace Spatie\Permission\Models;

use Spatie\Permission\Guard;
use Illuminate\Support\Collection;
use Spatie\Permission\Traits\HasRoles;
use Illuminate\Database\Eloquent\Model;
use Spatie\Permission\PermissionRegistrar;
use Spatie\Permission\Traits\RefreshesPermissionCache;
use Illuminate\Database\Eloquent\Relations\MorphToMany;
use Spatie\Permission\Exceptions\PermissionDoesNotExist;
use Illuminate\Database\Eloquent\Relations\BelongsToMany;
use Illuminate\Support\Facades\DB;
use Spatie\Permission\Exceptions\PermissionAlreadyExists;
use Spatie\Permission\Contracts\Permission as PermissionContract;

class Permission extends Model implements PermissionContract
{
    use HasRoles;
    use RefreshesPermissionCache;

    protected $guarded = ['id'];

    public function __construct(array $attributes = [])
    {
        $attributes['guard_name'] = $attributes['guard_name'] ?? config('auth.defaults.guard');

        parent::__construct($attributes);

        $this->setTable(config('permission.table_names.permissions'));
    }


    /**
     * A permission can be applied to roles.
     */
    public function roles(): BelongsToMany
    {
        return $this->belongsToMany(
            config('permission.models.role'),
            config('permission.table_names.role_has_permissions'),
            'permission_id',
            'role_id'
        );
    }

    /**
     * Get the permission's global roles.
     * 
     * @return BelongsToMany
     */
    public function globalRoles(): BelongsToMany
    {
        return $this->rolesFor(null);
    }

    /**
     * Get the permission's roles for the given context.
     * 
     * @param null|Model $context
     * 
     * @return BelongsToMany
     */
    public function rolesFor(?Model $context): BelongsToMany
    {
        return $this->roles();
    }

    /**
     * A permission belongs to some users of the model associated with its guard.
     */
    public function users(): MorphToMany
    {
        return $this->morphedByMany(
            getModelForGuard($this->attributes['guard_name']),
            'model',
            config('permission.table_names.model_has_permissions'),
            'permission_id',
            config('permission.column_names.model_morph_key')
        );
    }

    /**
     * A permission belongs to some users of the model associated with its guard.
     */
    public function usersFor(?Model $context): MorphToMany
    {
        if ($context === null) {
            return $this->users()
                        ->wherePivot('context_type', 'global')
                        ->wherePivot('context_id', null)
                        ->withPivot([
                            'context_type',
                            'context_id'
                        ]);
        }

        $contextType = (new \ReflectionClass($context))->getName();

        return $this->users()
                    ->wherePivot('context_type', $contextType)
                    ->wherePivot('context_id', null)
                    ->withPivot([
                        'context_type',
                        'context_id'
                    ]);
    }

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
    public static function findByName(string $name, $guardName = null): PermissionContract
    {
        return self::findByNameFor(null, $name, $guardName);
    }

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
    public static function findByNameFor(?Model $context, string $name, $guardName = null): PermissionContract
    {
        $guardName = $guardName ?? Guard::getDefaultName(static::class);

        if ($context === null) {
            $contextType = 'global';
        } else {
            $contextType = (new \ReflectionClass($context))->getName();
        }
        
        $permission = static::getPermissions(['name' => $name, 'context_type' => $contextType, 'guard_name' => $guardName])->first();

        if (! $permission) {
            throw PermissionDoesNotExist::create($name, $guardName, $contextType);
        }

        return $permission;
    }

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
    public static function findById(int $id, $guardName = null): PermissionContract
    {
        return self::findByIdFor(null, $id, $guardName);
    }
    
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
    public static function findByIdFor(?Model $context, int $id, $guardName = null): PermissionContract
    {
        $guardName = $guardName ?? Guard::getDefaultName(static::class);

        if ($context === null) {
            $contextType = 'global';
        } else {
            $contextType = (new \ReflectionClass($context))->getName();
        }

        $permission = static::getPermissions(['id' => $id, 'context_type' => $contextType, 'guard_name' => $guardName])->first();

        if (! $permission) {
            throw PermissionDoesNotExist::withId($id, $guardName, $contextType);
        }

        return $permission;
    }
    
    /**
     * Create a Permission
     * 
     * @param array $attributes 
     * 
     * @return Model|Builder 
     * @throws PermissionAlreadyExists 
     */
    public static function create(array $attributes = [])
    {
        $attributes['guard_name'] = $attributes['guard_name'] ?? Guard::getDefaultName(static::class);
        $attributes['context_type'] = $attributes['context_type'] ?? 'global';

        $permission = static::getPermissions(['name' => $attributes['name'], 'context_type' => $attributes['context_type'], 'guard_name' => $attributes['guard_name']])->first();

        if ($permission) {
            throw PermissionAlreadyExists::create($attributes['name'], $attributes['guard_name'], $attributes['context_type']);
        }

        return static::query()->create($attributes);
    }

    /**
     * Find or create a global permission by its name (and optionally guardName).
     *
     * @param string $name
     * @param string|null $guardName
     *
     * @return \Spatie\Permission\Contracts\Permission
     */
    public static function findOrCreate(string $name, $guardName = null): PermissionContract
    {
        return self::findOrCreateFor(null, $name, $guardName);
    }

    /**
     * Find or create permission by its name (and optionally guardName) for the given context.
     *
     * @param null|Model $context
     * @param string $name
     * @param string|null $guardName
     *
     * @return \Spatie\Permission\Contracts\Permission
     */
    public static function findOrCreateFor(?Model $context, string $name, $guardName = null): PermissionContract
    {
        $guardName = $guardName ?? Guard::getDefaultName(static::class);

        if ($context === null) {
            $contextType = 'global';
        } else {
            $contextType = (new \ReflectionClass($context))->getName();
        }

        $permission = static::getPermissions(['name' => $name, 'context_type' => $contextType, 'guard_name' => $guardName])->first();

        if (! $permission) {
            return static::query()->create(['name' => $name, 'context_type' => $contextType, 'guard_name' => $guardName]);
        }

        return $permission;
    }

    /**
     * Get the current cached permissions.
     */
    protected static function getPermissions(array $params = []): Collection
    {
        return app(PermissionRegistrar::class)
            ->setPermissionClass(static::class)
            ->getPermissions($params);
    }

    /**
     * Attach a related model to the permission for a given context
     *
     * @param Model|null $context
     * @param array $attributes
     * @return void
     */
    public function attachFor(?Model $context, array $attributes = [])
    {
        if ($attributes['model_type'] === config('permission.models.role')) {
            $morphKey = config('permission.column_names.model_morph_key');
            $this->roles()->attach($attributes[$morphKey]);
        }

        if ($context !== null) {
            $contextType = (new \ReflectionClass($context))->getName();
            $contextId = $context->id;
        } else {
            $contextType = 'global';
            $contextId = null;
        }

        $attributes['permission_id'] = $this->id;
        $attributes['context_type'] = $contextType;
        $attributes['context_id'] = $contextId;

        
        DB::table(config('permission.table_names.model_has_permissions'))
            ->insert($attributes);
    }
}
