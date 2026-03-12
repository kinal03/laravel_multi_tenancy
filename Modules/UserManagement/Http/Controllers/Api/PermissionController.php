<?php

namespace Modules\UserManagement\Http\Controllers\Api;

use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Spatie\Permission\Models\Permission;
use App\Models\User;
use App\Models\Tenant;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\DB;

class PermissionController extends Controller
{
    private function runInTenant(?string $tenantId, \Closure $callback)
    {
        if ($tenantId) {
            $tenant = Tenant::findOrFail($tenantId);
            tenancy()->initialize($tenant);
            //When running inside a tenant, use the tenant guard by default
            config(['auth.defaults.guard' => 'tenant_api']);
            $result = $callback();
            tenancy()->end();
            config(['auth.defaults.guard' => 'sanctum']);
            return $result;
        }

        //Ensure central/default guard is used for central DB operations
        config(['auth.defaults.guard' => 'sanctum']);
        return $callback(); // Central DB
    }

    public function index(Request $request): JsonResponse
    {
        $permissionName = $request->filled('tenant_id')
            ? 'tenant-permission-access'
            : 'permission-access';

        // Clear Spatie permission cache (debug or if roles/permissions change frequently)
        app()[PermissionRegistrar::class]->forgetCachedPermissions();

        if (!$request->user()->hasPermissionTo($permissionName, 'sanctum')) {
            return response()->json([
                'message' => 'Access Denied.',
                'required_permission' => $permissionName,
            ], 403);
        }

        return $this->runInTenant($request->tenant_id, function () use ($request) {

            /*
            |--------------------------------------
            | Cache Key (Tenant Safe)
            |--------------------------------------
            */

            $cacheKey = 'permissions_list_' . ($request->tenant_id ?? 'central') . '_' . md5($request->fullUrl());

            $permissions = Cache::tags(['permissions_list'])->rememberForever($cacheKey, function () {

                return Permission::orderBy('name')->paginate(10);

            });

            return response()->json([
                'permissions' => $permissions
            ]);
        });
    }

    public function store(Request $request): JsonResponse
    {
       $permissionName = $request->filled('tenant_id')
            ? 'tenant-permission-create'
            : 'permission-create';

        // Clear permission cache (temporary for debug)
        app()[\Spatie\Permission\PermissionRegistrar::class]->forgetCachedPermissions();

        if (!$request->user()->hasPermissionTo($permissionName, 'sanctum')) {
            return response()->json([
                'message' => 'Access Denied.',
                'required_permission' => $permissionName,
            ], 403);
        }

        return $this->runInTenant($request->tenant_id, function () use ($request) {
            $validated = $request->validate([
                'name' => 'required|string|unique:permissions,name',
            ]);

            $permission = Permission::create([
                'name' => $validated['name'],
                'guard_name' => 'sanctum',
            ]);

            Cache::tags(['permissions_list'])->flush();
            Cache::tags(['roles_list'])->flush();
            return response()->json([
                'message' => 'Permission created successfully',
                'permission' => $permission
            ], 201);
        });
    }

    public function show(Request $request, int $id): JsonResponse
    {
        $permissionName = $request->filled('tenant_id')
            ? 'tenant-permission-show'
            : 'permission-show';

        // Clear permission cache (temporary for debug)
        app()[\Spatie\Permission\PermissionRegistrar::class]->forgetCachedPermissions();    

        if (!$request->user()->hasPermissionTo($permissionName, 'sanctum')) {
            return response()->json([
                'message' => 'Access Denied.',
                'required_permission' => $permissionName,
            ], 403);
        }

        return $this->runInTenant($request->tenant_id, function () use ($id) {
            $permission = Permission::find($id);
            if (!$permission) {
                return response()->json(['message' => 'Permission not found'], 404);
            }
            
            return response()->json([
                'permission' => $permission
            ]);
        });
    }

    public function update(Request $request, int $id): JsonResponse
    {   
        $permissionName = $request->filled('tenant_id')
            ? 'tenant-permission-edit'
            : 'permission-edit';

        // Clear permission cache (temporary for debug)
        app()[\Spatie\Permission\PermissionRegistrar::class]->forgetCachedPermissions();    

        if (!$request->user()->hasPermissionTo($permissionName, 'sanctum')) {
            return response()->json([
                'message' => 'Access Denied.',
                'required_permission' => $permissionName,
            ], 403);
        }

        return $this->runInTenant($request->tenant_id, function () use ($request, $id) {

            $validated = $request->validate([
                'name' => 'required|string|unique:permissions,name,' . $id,
            ]);

            $permission = Permission::findOrFail($id);
            $permission->update($validated);

            Cache::tags(['permissions_list'])->flush();
            Cache::tags(['roles_list'])->flush();

            return response()->json([
                'message' => 'Permission updated successfully',
                'permission' => $permission
            ]);
        });
    }

    public function destroy(Request $request, int $id): JsonResponse
    {   
        $permissionName = $request->filled('tenant_id')
            ? 'tenant-permission-delete'
            : 'permission-delete';

        // Clear permission cache (temporary for debug)
        app()[\Spatie\Permission\PermissionRegistrar::class]->forgetCachedPermissions();    

        if (!$request->user()->hasPermissionTo($permissionName, 'sanctum')) {
            return response()->json([
                'message' => 'Access Denied.',
                'required_permission' => $permissionName,
            ], 403);
        }

        return $this->runInTenant($request->tenant_id, function () use ($id) {
            
            $permission = Permission::find($id);
            if (!$permission) {
                return response()->json(['message' => 'Permission not found in tenant'], 404);
            }
            
            $permission->delete();

            Cache::tags(['permissions_list'])->flush();
            Cache::tags(['roles_list'])->flush();

            return response()->json([
                'message' => 'Permission deleted successfully'
            ]);
        });
    }

    public function assignToUser(Request $request, int $permissionId): JsonResponse
    {
        return $this->runInTenant($request->tenant_id, function () use ($request, $permissionId) {

            $validated = $request->validate([
                'user_id' => 'required|exists:users,id',
            ]);

            $user = User::findOrFail($validated['user_id']);
            $permission = Permission::findOrFail($permissionId);

            $user->givePermissionTo($permission);

            return response()->json([
                'message' => 'Permission assigned to user successfully',
                'user' => $user->load('permissions')
            ]);
        });
    }
}
