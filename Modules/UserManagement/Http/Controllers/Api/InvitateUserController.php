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
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\URL;
use Laravel\Sanctum\PersonalAccessToken;
use Illuminate\Support\Facades\Crypt;
use Illuminate\Validation\Rule;
 
class InvitateUserController extends Controller
{  
    public function invite(Request $request): JsonResponse
    {
        $user_id = $request->user()->id;
        $user = User::find($user_id);
 
        // Base validation
        $rules = [
            'name'  => 'required|string|max:255',
            'email' => [
                'required',
                'email',
                'max:255',
                Rule::unique('users', 'email'),
                Rule::unique('super_admin_invitations', 'email'),
            ],
            'user_type' => 'required|in:admin,agency,agent',
        ];
 
        // Extra validation for agent
        if ($request->user_type === 'agent') {
            $rules['tenant_id'] = 'required|exists:tenants,id';
        }
 
        $validator = Validator::make($request->all(), $rules);
 
        if ($validator->fails()) {
            return response()->json(['errors' => $validator->errors()], 422);
        }
 
        // Permission mapping
        $permissionMap = [
            'admin'  => 'admin-create',
            'agency' => 'agency-create',
            'agent'  => 'agent-create',
        ];
 
        if (!$user->can($permissionMap[$request->user_type])) {
            return response()->json(['message' => 'Access Denied.'], 403);
        }
 
        $Settings = Settings::where('key','expired_link_duration')->first();
        $expireDays = (int)$Settings->value ?? 1;
        
        // Create invitation
        $invitation = UserInvitations::create([
            'name'       => $request->name,
            'email'      => $request->email,
            'password'   => Hash::make(bin2hex(random_bytes(6))),
            'token'      => Str::random(64),
            'user_type'  => $request->user_type,
            'status'     => 'pending',
            'tenant_id'  => $request->user_type === 'agent' ? $request->tenant_id : null,
            'expires_at' => now()->addDays($expireDays),
            'created_by' => $user->id,
        ]);
 
        $inviter = $user;
 
        $payload = [
            'token' => $invitation->token,
            'email' => $invitation->email,
            'name'  => $request->name,
        ];
 
        $encrypted = Crypt::encryptString(json_encode($payload));
 
        $frontendUrl = config('app.frontend_url'). '/accept-invitation?data=' . urlencode($encrypted);
        
        // Send email once
        Mail::to($request->email)->send(new \App\Mail\UserInvitationMail($invitation, $inviter,$frontendUrl));

        Cache::tags(['invitation_list_user_' . $user->id])->flush();

 
        return response()->json([
            'message' => 'Invitation sent successfully.'
        ]);
    }

    public function resendInvite(Request $request): JsonResponse
    {
        $user_id = $request->user()->id;
        $user = User::find($user_id);
 
        $request->validate([
            'email' => 'required|email',
            'user_type' => 'required|in:admin,agency,agent',
        ]);
 
        // Permission check
        $permissionMap = [
            'admin'  => 'admin-create',
            'agency' => 'agency-create',
            'agent'  => 'agent-create',
        ];
 
        if (!$user->can($permissionMap[$request->user_type])) {
            return response()->json(['message' => 'Access Denied.'], 403);
        }
 
        // 🔎 Check invitation only if expired OR rejected
        $invitation = UserInvitations::where('email', $request->email)
            ->where('user_type', $request->user_type)
            ->whereIn('status', ['expired', 'rejected'])
            ->first();
 
        if (!$invitation) {
            return response()->json([
                'message' => 'Only expired or rejected invitations can be resent.'
            ], 422);
        }
 
        $Settings = Settings::where('key','expired_link_duration')->first();
        $expireDays = $Settings->value ?? 1;
 
        // ✅ Regenerate token & activate again
        $invitation->update([
            'token'      => Str::random(64),
            'status'     => 'pending',
            'expires_at' => now()->addDays($expireDays),
        ]);
 
        $payload = [
            'token' => $invitation->token,
            'email' => $invitation->email,
            'name'  => $invitation->name,
        ];
 
        $encrypted = Crypt::encryptString(json_encode($payload));
 
        $frontendUrl = config('app.frontend_url')
            . '/accept-invitation?data=' . urlencode($encrypted);
 
        Mail::to($invitation->email)
            ->send(new \App\Mail\UserInvitationMail($invitation, $user, $frontendUrl));
 
        return response()->json([
            'message' => 'Invitation resent successfully.'
        ]);
    }
 
    public function accept(Request $request)
    {
        $request->validate([
            'data' => 'required',
            'password' => 'required|confirmed'
        ]);
 
        try {
             $decoded = urldecode($request->data);
 
            $decrypted = json_decode(
                \Crypt::decryptString($decoded),
                true
            );
        } catch (\Exception $e) {
            return response()->json([
                'message' => 'Invalid or corrupted invitation link.'
            ], 400);
        }
 
        $invitation = UserInvitations::where('token', $decrypted['token'])
            ->where('status', 'pending')
            ->first();
 
        if (!$invitation) {
            return response()->json([
                'message' => 'Invitation not found or already used.'
            ], 404);
        }
 
        if ($invitation->expires_at->isPast()) {
            $invitation->update(['status' => 'expired']);
             return response()->json([
                'message' => 'Invitation expired.'
            ], 403);
        }
 
        /* ================= ADMIN ================= */
        if ($invitation->user_type === 'admin') {

            $user = User::create([
                'name' => $invitation->name,
                'email' => $invitation->email,
                'password' => Hash::make($request->password),
                'user_type' => 'super_admin',
                'email_verified_at' => now(),
            ]);

            $role = Role::firstOrCreate([
                'name' => 'admin',
                'guard_name' => 'sanctum'
            ]);

            $permissions = $this->getPermissionsForRole('admin');
            $role->syncPermissions($permissions);

            $user->assignRole($role);
        }

        /* ================= AGENCY ================= */
        elseif ($invitation->user_type === 'agency') {

            $tenant = Tenant::create([
                'id' => Str::uuid()->toString(),
                'agency_name' => $invitation->name,
                'database' => 'tenant' . Str::random(8),
            ]);

            Artisan::call('tenants:migrate', [
                '--tenants' => [$tenant->id]
            ]);

            $user = User::create([
                'name' => $invitation->name,
                'email' => $invitation->email,
                'password' => Hash::make($request->password),
                'user_type' => 'agency',
                'email_verified_at' => now(),
                'tenant_id' => $tenant->id,
            ]);

            $role = Role::firstOrCreate([
                'name' => 'agency',
                'guard_name' => 'sanctum'
            ]);

            $permissions = $this->getPermissionsForRole('agency');
            $role->syncPermissions($permissions);

            $user->assignRole($role);

            tenancy()->initialize($tenant);
            $allPermissions = collect([
                'agent-create',
                'agent-edit',
                'agent-show',
                'agent-delete',
            ])->map(function ($permission) {
                return Permission::firstOrCreate([
                    'name' => $permission,
                    'guard_name' => 'sanctum'
                ]);
            });

            /** -------------------------------------------------
             * CREATE OR GET SUPER ADMIN ROLE
             * -------------------------------------------------*/
            $superAdminRole = Role::firstOrCreate([
                'name' => 'agent',
                'guard_name' => 'sanctum',
            ]);

            /** -------------------------------------------------
             * GIVE ALL PERMISSIONS TO SUPER ADMIN
             * -------------------------------------------------*/
            $superAdminRole->syncPermissions($allPermissions);

            tenancy()->end();
            
            Cache::tags(['agency_list'])->flush();
        }

        /* ================= AGENT ================= */
        elseif ($invitation->user_type === 'agent') {

            $tenant = Tenant::find($invitation->tenant_id);

            if (!$tenant) {
                return;
            }

            CentralTenantTelations::create([
                'tenant_id' => $tenant->id,
                'email' => $invitation->email,
                'status' => 'active',
            ]);

            tenancy()->initialize($tenant);

            $user = User::create([
                'name' => $invitation->name,
                'email' => $invitation->email,
                'email_verified_at' => now(),
                'password' => Hash::make($request->password),
            ]);

            // $role = Role::firstOrCreate([
            //     'name' => 'agent',
            //     'guard_name' => 'sanctum'
            // ]);

            // $permissions = collect([
            //     'agent-access',
            //     'agent-create',
            //     'agent-edit',
            //     'agent-show',
            //     'agent-delete',
            // ])->map(function ($permission) {
            //     return Permission::firstOrCreate([
            //         'name' => $permission,
            //         'guard_name' => 'sanctum'
            //     ]);
            // });

            // $role->syncPermissions($permissions);
            // $user->assignRole($role);

            tenancy()->end();
            Cache::tags(['agents_list'])->flush();
        }

        /* ================= INVALID ================= */
        else {
            return response()->json([
                'message' => 'Something went wrong.',
            ], 500);
        }

        $invitation->update([
            'status' => 'accepted'
        ]);
 
        Cache::tags(['users_list'])->flush();
        return response()->json([
            'message' => 'Account created successfully.'
        ]);
    }
 
    private function getPermissionsForRole(string $roleName)
    {
        $map = [
            'super_admin' => ['%'], // all permissions
            'admin' => ['admin', 'agency', 'agent'],
            'agency' => ['agency', 'agent'],
            'agent' => ['agent'],
        ];
 
        if ($roleName === 'main_super_admin') {
            return Permission::pluck('name')->toArray();
        }
 
        $groups = $map[$roleName] ?? [];
 
        return Permission::where(function ($q) use ($groups) {
            foreach ($groups as $group) {
                $q->orWhere('name', 'like', $group . '-%');
            }
        })->pluck('name')->toArray();
    }

    public function invitationList(Request $request): JsonResponse
    {
        $user = $request->user();
        // $user = User::find(1);


        // Create unique cache key based on URL + user
        $cacheKey = 'invitation_list_user_' . $user->id . '_' . md5($request->fullUrl());

        $invitations = Cache::remember($cacheKey, 300, function () use ($request, $user) {

            $query = UserInvitations::select('id', 'name', 'email', 'user_type', 'status', 'created_at')
                ->where('created_by', $user->id);

            if ($request->has('status')) {
                $query->where('status', $request->status);
            }

            if ($request->has('user_type')) {
                $query->where('user_type', $request->user_type);
            }

            if ($request->has('search')) {
                $query->where(function ($q) use ($request) {
                    $q->where('name', 'like', '%' . $request->search . '%')
                    ->orWhere('email', 'like', '%' . $request->search . '%');
                });
            }

            return $query->paginate(10);
        });

        return response()->json([
            'message' => 'Invitation list retrieved successfully',
            'status' => true,
            'data' => $invitations
        ]);
    }
}