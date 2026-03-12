<?php

namespace Modules\UserManagement\Http\Controllers\Api;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Spatie\Permission\Models\Role;
use Spatie\Permission\Models\Permission;
use App\Models\User;
use App\Models\Tenant;
use Illuminate\Support\Facades\Cache;


class RoleController extends Controller
{
    private function runInTenant(?string $tenantId, \Closure $callback)
    {
        if ($tenantId) {
            $tenant = Tenant::findOrFail($tenantId);
            tenancy()->initialize($tenant);
            // When running inside a tenant, use the tenant guard by default
            config(['auth.defaults.guard' => 'tenant_api']);

            $result = $callback();

            // reset to central guard after tenant work
            tenancy()->end();
            config(['auth.defaults.guard' => 'sanctum']);
            return $result;
        }

        // Ensure central/default guard is used for central DB operations
        config(['auth.defaults.guard' => 'sanctum']);

        return $callback(); // Central DB
    }

    public function index(Request $request): JsonResponse
    {   
        return $this->runInTenant($request->tenant_id, function () use ($request) {

            $permission = $request->filled('tenant_id')
                ? 'tenant-role-access'
                : 'role-access';

            if (!$request->user()->can($permission)) {
                return response()->json(['message' => 'Access Denied.'], 403);
            }

            /*
            |-----------------------------------------
            | Create Cache Key (Tenant Safe)
            |-----------------------------------------
            */

            $cacheKey = 'roles_list_' . ($request->tenant_id ?? 'central') . '_' . md5($request->fullUrl());

            $roles = Cache::tags(['roles_list'])->rememberForever($cacheKey, function () use ($request) {

                if ($request->select == true) {

                    return Role::select('id', 'name')
                        ->orderBy('name')
                        ->get();

                } else {

                    $limit = $request->limit ?? 10;
                    $sort  = $request->sort ?? 'created_at';
                    $dir   = $request->dir ?? 'desc';

                    $query = Role::with('permissions');

                    if ($request->filled('search')) {
                        $search = $request->search;

                        $query->where(function ($q) use ($search) {
                            $q->where('name', 'like', "%{$search}%")
                            ->orWhereHas('permissions', function ($q2) use ($search) {
                                $q2->where('name', 'like', "%{$search}%");
                            });
                        });
                    }

                    return $query->orderBy($sort, $dir)->paginate($limit);
                }

            });

            return response()->json([
                'roles' => $roles
            ]);
        });
    }

    public function store(Request $request): JsonResponse
    {
        return $this->runInTenant($request->tenant_id, function () use ($request) {
            $permission = $request->filled('tenant_id')
                ? 'tenant-role-create'
                : 'role-create';

            if (!$request->user()->can($permission)) {
                return response()->json(['message' => 'Access Denied.'], 403);
            }

            $validated = $request->validate([
                'name' => 'required|string|unique:roles,name',
                'permissions' => 'array',
                'permissions.*' => 'exists:permissions,id',
            ]);

            $role = Role::create([
                'name' => $validated['name'],
                'guard_name' => 'sanctum'
            ]);

            if (!empty($validated['permissions'])) {
                $role->syncPermissions($validated['permissions']);
            }

            Cache::tags(['roles_list'])->flush();

            return response()->json([
                'message' => 'Role created successfully',
                'role' => $role->load('permissions')
            ], 201);
        });
    }

    public function show(Request $request, int $id): JsonResponse
    {
        return $this->runInTenant($request->tenant_id, function () use ($request, $id) {
            $permission = $request->filled('tenant_id')
                ? 'tenant-role-show'
                : 'role-show';

            if (!$request->user()->can($permission)) {
                return response()->json(['message' => 'Access Denied.'], 403);
            }

            $role = Role::with('permissions')->find($id);
            if (!$role) {
                return response()->json(['message' => 'Role not found'], 404);
            }
        
            return response()->json([
                'role' => $role
            ]);
        });
    }

    public function update(Request $request, int $id): JsonResponse
    {
        return $this->runInTenant($request->tenant_id, function () use ($request, $id) {

            $permission = $request->filled('tenant_id')
                ? 'tenant-role-edit'
                : 'role-edit';

            if (!$request->user()->can($permission)) {
                return response()->json(['message' => 'Access Denied.'], 403);
            }

            $validated = $request->validate([
                'name' => 'required|string|unique:roles,name,' . $id,
                'permissions' => 'array',
                'permissions.*' => 'exists:permissions,id',
            ]);

            $role = Role::findOrFail($id);
            $role->update(['name' => $validated['name']]);

            if (isset($validated['permissions'])) {
                $role->syncPermissions($validated['permissions']);
            }

            Cache::tags(['roles_list'])->flush();

            return response()->json([
                'message' => 'Role updated successfully',
                'role' => $role->load('permissions')
            ]);
        });
    }

    public function destroy(Request $request, int $id): JsonResponse
    {
        return $this->runInTenant($request->tenant_id, function () use ($id) {
            $permission = $request->filled('tenant_id')
                ? 'tenant-role-delete'
                : 'role-delete';

            if (!$request->user()->can($permission)) {
                return response()->json(['message' => 'Access Denied.'], 403);
            }

            $role = Role::find($id);
            if (!$role) {
                return response()->json(['message' => 'Role not found'], 404);
            }
            $role->delete();

            Cache::tags(['roles_list'])->flush();

            return response()->json([
                'message' => 'Role deleted successfully'
            ]);
        });
    }

    public function assignToUser(Request $request, int $roleId): JsonResponse
    {
        return $this->runInTenant($request->tenant_id, function () use ($request, $roleId) {

            $validated = $request->validate([
                'user_id' => 'required|exists:users,id',
            ]);

            $user = User::findOrFail($validated['user_id']);
            $role = Role::findOrFail($roleId);

            $user->assignRole($role);

            Cache::tags(['roles_list'])->flush();

            return response()->json([
                'message' => 'Role assigned to user successfully',
                'user' => $user->load('roles.permissions')
            ]);
        });
    }
}
