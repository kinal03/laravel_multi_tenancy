<?php
 
namespace Modules\UserManagement\Http\Controllers\Api;
 
use App\Models\User;
use App\Models\Settings;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\Hash;
use Illuminate\Validation\ValidationException;
use Stancl\Tenancy\Exceptions\DomainOccupiedByOtherTenantException;
use Stancl\Tenancy\Database\Models\Domain as TenancyDomain;
use Illuminate\Support\Str;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Validator;
use App\Models\Tenant,App\Models\CentralTenantTelations,App\Models\UserInvitations;
use Spatie\Permission\Models\Role;
use Spatie\Permission\Models\Permission;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\URL;
use Laravel\Sanctum\PersonalAccessToken;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Validation\Rule;
 
class UserController extends Controller
{  
    public function getUsers(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'user_type' => 'nullable|in:admin,agency',
            'search'   => 'nullable|string|max:255',
        ]);
 
        if ($validator->fails()) {
            return response()->json(['errors' => $validator->errors()], 422);
        }
 
        // Permission mapping
        $permissionMap = [
            'admin'  => 'admin-access',
            'agency' => 'agency-access',
        ];

        if($request->user_type != ''){
            if (!$request->user()->can($permissionMap[$request->user_type])) {
                return response()->json(['message' => 'Access Denied.'], 403);
            }
        }

        // Default values
        $limit = $request->limit ?? 10;
        $sort  = $request->sort ?? 'created_at';
        $dir   = $request->dir ?? 'desc';
 
        $users = User::whereHas('roles', function ($q) use ($request) {
            if($request->user_type != ''){
                $q->where('name', $request->user_type);
            }
        });
 
        // Search filter
        if ($request->filled('search')) {
            $search = $request->search;
            $users->where(function ($q) use ($search) {
                $q->where('name', 'like', "%{$search}%")
                ->orWhere('email', 'like', "%{$search}%");
            });
        }

        $users->orderBy($sort, $dir);
 
        return response()->json([
            'status' => true,
            'users'  => $users->paginate($limit),
        ], 200);
    }
 
    public function getAgents(Request $request)
    {
        if (!$request->user()->can('agent-access')) {
            return response()->json(['message' => 'Access Denied.'], 403);
        }
 
        $validator = Validator::make($request->all(), [
            'tenant_id' => 'required|exists:tenants,id',
        ]);
 
        if ($validator->fails()) {
            return response()->json(['errors' => $validator->errors()], 422);
        }
 
        $tenant = Tenant::find($request->tenant_id);
 
        if (!$tenant) {
            return response()->json(['message' => 'Agency not found.'], 404);
        }
 
        tenancy()->initialize($tenant);
 
            $agent = User::select('id','name','email');
 
            if ($request->filled('search')) {
                $search = $request->search;
 
                $agent = $agent->where(function ($q) use ($search) {
                    $q->where('name', 'like', "%{$search}%")
                    ->orWhere('email', 'like', "%{$search}%");
                });
            }
 
            $agent = $agent->paginate(10);
 
        tenancy()->end();
 
        return response()->json([
            'agents' => $agent
        ],200);
    }
 
    public function getUserDetails(Request $request)
    {
        $Auth = $request->user();
 
        $validator = Validator::make($request->all(), [
            'id' => 'required',
        ]);
 
        if ($validator->fails()) {
            return response()->json(['errors' => $validator->errors()], 422);
        }
 
        if($request->filled('tenant_id')){
            if (!$request->user()->can('agent-show')) {
                return response()->json(['message' => 'Access Denied.'], 403);
            }
            $tenant = Tenant::find($request->tenant_id);
 
            if (!$tenant) {
                return response()->json(['message' => 'Tenant not found.'], 404);
            }
 
            tenancy()->initialize($tenant);
            $user = User::find($request->id);

            if (!$user) {
                return response()->json(['message' => 'User not found.'], 404);
            }
            
            // $user->load('roles.permissions','tenant');
            $user->load('roles','tenant');

            tenancy()->end();
        } else {
            $user = User::find($request->id);
 
            if($request->user_type == 'admin'){
                $permissionName = 'admin-show';
            } else {
                $permissionName = 'agency-show';
            }
 
            if (!$request->user()->can($permissionName)) {
                return response()->json(['message' => 'Access Denied.'], 403);
            }
       
            // $user->load('roles.permissions','tenant');
            $user->load('roles','tenant');
        }
       
        return response()->json([
            'user' => $user
        ],200);
    }
 
    public function updateUser(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'id'    => 'required|integer|exists:users,id',
            'name'  => 'nullable|string|max:255',
            'email' => 'nullable|email|max:255',
            'tenant_id' => 'nullable|integer|exists:tenants,id',
        ]);
 
        if ($validator->fails()) {
            return response()->json(['errors' => $validator->errors()], 422);
        }
 
        // TENANT USER UPDATE
        if ($request->filled('tenant_id')) {
 
            if (!$request->user()->can('agent-edit')) {
                return response()->json(['message' => 'Access Denied.'], 403);
            }
 
            $tenant = Tenant::find($request->tenant_id);
            tenancy()->initialize($tenant->id);
 
            $user = User::find($request->id);
 
            if (!$user) {
                tenancy()->end();
                return response()->json(['message' => 'User not found.'], 404);
            }
 
            $user->update([
                'name'  => $request->name ?? $user->name,
                'email' => $request->email ?? $user->email,
            ]);
 
            tenancy()->end();
 
        }
        // CENTRAL USER UPDATE
        else {
 
            $user = User::find($request->id);
 
            if (!$user) {
                return response()->json(['message' => 'User not found.'], 404);
            }
 
            // Decide permission based on ACTUAL user role
            if ($user->hasRole('admin')) {
                $permissionName = 'admin-edit';
            } else {
                $permissionName = 'agency-edit';
            }
 
            if (!$request->user()->can($permissionName)) {
                return response()->json(['message' => 'Access Denied.'], 403);
            }
 
            $user->update([
                'name'  => $request->name ?? $user->name,
                'email' => $request->email ?? $user->email,
            ]);
 
            if ($request->filled('agency_name') && $user->tenant_id) {
                $tenant = Tenant::find($user->tenant_id);
                if ($tenant) {
                    $tenant->update([
                        'agency_name' => $request->agency_name,
                    ]);
                }
            }
        }
 
        return response()->json([
            'status'  => true,
            'message' => 'User updated successfully.',
        ], 200);
    }

    public function deleteUser(Request $request, $userId): JsonResponse
    {
        $tenantId = $request->tenant_id ?? null;

        DB::beginTransaction();

        try {

            /*
            |--------------------------------------------------------------------------
            | CASE 1: Only Tenant Delete (id + tenant_id)
            |--------------------------------------------------------------------------
            */
            if ($tenantId) {

                $tenant = Tenant::find($tenantId);

                if (!$tenant) {
                    return response()->json([
                        'status' => false,
                        'message' => 'Tenant not found.'
                    ], 404);
                }

                tenancy()->initialize($tenant);

                $tenantUser = \App\Models\Tenant\User::find($userId);

                if (!$tenantUser) {
                    tenancy()->end();

                    return response()->json([
                        'status' => false,
                        'message' => 'User not found in tenant database.'
                    ], 404);
                }

                $tenantUser->delete();

                tenancy()->end();

                DB::commit();

                return response()->json([
                    'status' => true,
                    'message' => 'Tenant user deleted successfully.'
                ]);
            }

            /*
            |--------------------------------------------------------------------------
            | CASE 2: Central Delete (Only ID)
            |--------------------------------------------------------------------------
            */

            tenancy()->end(); // Ensure central DB

            $centralUser = User::find($userId);

            if (!$centralUser) {
                return response()->json([
                    'status' => false,
                    'message' => 'User not found in central database.'
                ], 404);
            }

            // Soft delete central
            $centralUser->delete();

            // Deactivate relation
            CentralTenantTelations::where('email', $centralUser->email)
                ->update(['status' => 'deactive']);

            /*
            |--------------------------------------------------------------------------
            | If user has agency role → delete from all tenants
            |--------------------------------------------------------------------------
            */

            if ($centralUser->hasRole('agency')) {

                $tenants = Tenant::all();

                foreach ($tenants as $tenant) {

                    tenancy()->initialize($tenant);

                    $tenantUser = \App\Models\Tenant\User::where('email', $centralUser->email)->first();

                    if ($tenantUser) {
                        $tenantUser->delete();
                    }

                    tenancy()->end();
                }
            }

            DB::commit();

            return response()->json([
                'status' => true,
                'message' => 'User deleted successfully from central and related tenants.'
            ]);

        } catch (\Exception $e) {

            DB::rollBack();
            tenancy()->end();

            return response()->json([
                'status' => false,
                'message' => 'Something went wrong.',
                'error' => $e->getMessage()
            ], 500);
        }
    }
}