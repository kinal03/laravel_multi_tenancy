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
use App\Models\Tenant;
use App\Models\CentralTenantTelations;
use Spatie\Permission\Models\Role;
use Spatie\Permission\Models\Permission;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\URL;
use Laravel\Sanctum\PersonalAccessToken;
use Illuminate\Validation\Rule;
use PragmaRX\Google2FAQRCode\Google2FA;
use BaconQrCode\Renderer\ImageRenderer;
use BaconQrCode\Renderer\Image\SvgImageBackEnd;
use BaconQrCode\Renderer\RendererStyle\RendererStyle;
use BaconQrCode\Writer;
use Carbon\Carbon;

class AuthController extends Controller
{   
    private function getPermissionsForRole(string $roleName)
    {
        $map = [
            'super_admin' => ['%'], // all permissions
            'admin' => ['admin', 'agency', 'agent'],
            'agency' => ['agency', 'agent'],
            'agent' => ['agent'],
        ];

        if ($roleName === 'super_admin') {
            return Permission::pluck('name')->toArray();
        }

        $groups = $map[$roleName] ?? [];

        return Permission::where(function ($q) use ($groups) {
            foreach ($groups as $group) {
                $q->orWhere('name', 'like', $group . '-%');
            }
        })->pluck('name')->toArray();
    }

    public function register(Request $request): JsonResponse
    {   
        $validator = Validator::make($request->all(), [
            'name' => ['required', 'string', 'max:255'],
            'email' => [
                'required',
                'string',
                'email',
                'max:255',
                Rule::unique('users')->where(function ($query) {
                    return $query->whereNull('deleted_at');
                }),
            ],
            'password' => ['required', 'min:6'],
        ]);

        if ($validator->fails()) {
            return response()->json(['errors' => $validator->errors()], 422);
        }

        $tenant = Tenant::create([
            'id' => Str::uuid()->toString(),
            'agency_name' => $request->name,
            'database' => 'tenant' . Str::random(8),
        ]);

        Artisan::call('tenants:migrate', [
            '--tenants' => [$tenant->id]
        ]); 

        $tenantUser = User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => Hash::make($request->password),
            'user_type' => 'agency',
            'tenant_id' => $tenant->id
        ]);

        $role = Role::firstOrCreate([
            'name' => 'agency',
            'guard_name' => 'sanctum'
        ]);

        // $permissions = $this->getPermissionsForRole('agency');
        // $role->syncPermissions($permissions);

        $tenantUser->assignRole($role);

        // Access Token (15 minutes)
        // $token = $tenantUser->createToken('auth-token', ['*'], now()->addMinutes(10))->plainTextToken;

        // $accessToken->accessToken->token_type = 'access';
        // $accessToken->accessToken->expires_at = now()->addMinutes(10);
        // $accessToken->accessToken->save();

        // // Refresh Token (7 days)
        // $refreshToken = $tenantUser->createToken(
        //     'refresh_token',
        //     ['refresh'],
        //     now()->addMinutes(30)
        // );

        // $refreshToken->accessToken->token_type = 'refresh';
        // $refreshToken->accessToken->expires_at = now()->addMinutes(30);
        // $refreshToken->accessToken->save();

        $tenantUser->sendEmailVerificationNotification();

        tenancy()->initialize($tenant);
        $allPermissions = collect([
            'agent-access',
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

        return response()->json([
            'status' => true,
            'message' => 'Your accountregistered successfully',
            // 'user' => $tenantUser->load('roles.permissions'),
            //'token' => $token,
            // 'tenant' => $tenant
        ]);
    }

    public function resendVerificationEmail(Request $request){
        $user = $request->user();

        if ($user->hasVerifiedEmail()) {
            return response()->json([
                'message' => 'Email already verified.'
            ], 400);
        }

        $user->sendEmailVerificationNotification();

        return response()->json([
            'message' => 'Verification link sent successfully.'
        ], 200);
    }

    public function old_register(Request $request): JsonResponse
    {   
        $validator = Validator::make($request->all(), [
            'name' => 'required|string|max:255',
            'email' => 'required|string|email|max:255|unique:users',
            'password' => 'required|min:6',
            // 'role_id' => 'required|exists:roles,id',
        ]);

        if ($validator->fails()) {
            return response()->json(['errors' => $validator->errors()], 422);
        }

        if (!$request->tenant_id) {
            $role = Role::where('guard_name', 'sanctum')->find($request->role_id);

            if (!$role) {
                return response()->json(['message' => 'Invalid central role'], 422);
            }

            $roleName = strtolower($role->name);

            if ($roleName === 'admin') {
                $user = User::create([
                    'name' => $request->name,
                    'email' => $request->email,
                    'password' => Hash::make($request->password),
                    'user_type' => 'super_admin'
                ]);

                $role = Role::firstOrCreate([
                    'name' => $roleName,
                    'guard_name' => 'sanctum'
                ]);

                $permissions = $this->getPermissionsForRole($roleName);
                
                $role->syncPermissions($permissions);

                $user->assignRole($role);

                $token = $user->createToken('auth-token')->plainTextToken;

                $user->sendEmailVerificationNotification();

                return response()->json([
                    'status' => true,
                    'message' => 'Super admin registered successfully',
                    'user' => $user->load('roles.permissions'),
                    'token' => $token,
                    'tenant' => null
                ]);
            }

            if ($roleName === 'agency') {
                $tenant = Tenant::create([
                    'id' => Str::uuid()->toString(),
                    'agency_name' => $request->name,
                    'database' => 'tenant' . Str::random(8),
                ]);

                Artisan::call('tenants:migrate', [
                    '--tenants' => [$tenant->id]
                ]); 

                $tenantUser = User::create([
                    'name' => $request->name,
                    'email' => $request->email,
                    'password' => Hash::make($request->password),
                    'user_type' => 'agency',
                    'tenant_id' => $tenant->id
                ]);

                $role = Role::firstOrCreate([
                    'name' => 'agency',
                    'guard_name' => 'sanctum'
                ]);

                // $permissions = $this->getPermissionsForRole('agency');
                // $role->syncPermissions($permissions);

                $tenantUser->assignRole($role);

                $token = $tenantUser->createToken('auth-token')->plainTextToken;

                $tenantUser->sendEmailVerificationNotification();

                tenancy()->initialize($tenant);
                $allPermissions = collect([
                    'agent-access',
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

                return response()->json([
                    'status' => true,
                    'message' => 'Agency registered successfully',
                    'user' => $tenantUser->load('roles.permissions'),
                    'token' => $token,
                    'tenant' => $tenant
                ]);
            }
        }

        if ($request->tenant_id) {
            $tenant = Tenant::find($request->tenant_id);

            if (!$tenant) {
                return response()->json(['message' => 'Invalid tenant'], 404);
            }

            // Create relation in central DB
            CentralTenantTelations::create([
                'tenant_id' => $tenant->id,
                'email' => $request->email,
                'status' => 'active',
            ]);

            tenancy()->initialize($tenant);

            $tenantUser = User::create([
                'name' => $request->name,
                'email' => $request->email,
                'password' => Hash::make($request->password),
                //'user_type' => 'agent'
            ]);

            $role = Role::firstOrCreate([
                'name' => 'agent',
                'guard_name' => 'sanctum'
            ]);

           $permissions = collect([
                'agent-access',
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

            $role->syncPermissions($permissions);

            $tenantUser->assignRole($role);

            $token = $tenantUser->createToken('auth-token')->plainTextToken;

            // $tenantUser->sendEmailVerificationNotification();

            $verificationUrl = URL::temporarySignedRoute(
                'tenant.verification.verify',
                now()->addMinutes(60),
                [
                    'tenant' => $tenant->id,
                    'id' => $tenantUser->getKey(),
                    'hash' => sha1($tenantUser->getEmailForVerification()),
                ]
            );

            Mail::raw("Verify your email: $verificationUrl", function ($message) use ($tenantUser) {
                $message->to($tenantUser->email)
                        ->subject('Verify Email Address');
            });

            // tenancy()->end();

            return response()->json([
                'status' => true,
                'message' => 'Agent registered successfully',
                'user' => $tenantUser->load('roles.permissions'),
                'token' => $token,
                'tenant' => $tenant
            ]);
        }
    }

    public function loginOld(Request $request): JsonResponse
    {
        $request->validate([
            'email' => 'required|email',
            'password' => 'required',
        ]);

        tenancy()->end(); // Ensure we are in central DB

        $centralUser = User::select('id', 'name', 'email', 'password', 'email_verified_at', 'user_type')->where('email', $request->email)->first();

        if (isset($centralUser)) {

            // CENTRAL LOGIN
            if (!Hash::check($request->password, $centralUser->password)) {
                return response()->json([
                    'status' => false,
                    'message' => 'Invalid credentials.'
                ], 401);
            }

            if (is_null($centralUser->email_verified_at)) {
                return response()->json([
                    'status' => false,
                    'message' => 'Please verify your email.'
                ], 403);
            }

            $centralUser->tokens()->delete();

            // $remember = $request->remember_me ?? false;

            // if ($remember) {
            //     // 30 days expiry
            //     $token = $centralUser->createToken('auth-token', [], now()->addDays(30))->plainTextToken;
            // } else {
            //     // 1 day expiry
            //     $token = $centralUser->createToken('auth-token', [], now()->addDay())->plainTextToken;
            // }

            // Access Token (15 minutes)
            $token = $centralUser->createToken('auth-token', ['*'], now()->addMinutes(10));

            $accessToken = $token->accessToken;
            $accessToken->token_type = 'access';
            $accessToken->expires_at = now()->addMinutes(10);
            $accessToken->save();

            // Refresh Token (7 days)
            $refreshToken = $centralUser->createToken(
                'refresh_token',
                ['refresh'],
                now()->addMinutes(30)
            );

            $refreshToken->accessToken->token_type = 'refresh';
            $refreshToken->accessToken->expires_at = now()->addMinutes(30);
            $refreshToken->accessToken->save();

            if ($centralUser->tenant_id) {
                $tenant = Tenant::find($centralUser->tenant_id);
                $tenantData = [
                    'id' => $tenant->id,
                    'agency_name' => $tenant->agency_name,
                    'database' => $tenant->database
                ];
            } else {
                $tenantData = null;
            }

            // $centralUser->load('roles.permissions');

            return response()->json([
                'status' => true,
                'message' => 'User login successful',
                // 'user' => $centralUser,
                'token' => $token->plainTextToken,
                'refresh_token' => $refreshToken->plainTextToken,
                'tenant' => $tenantData
            ]);
        }

        // AGENT LOGIN (TENANT DB)
        $relation = CentralTenantTelations::where(['email' => $request->email, 'status' => 'active'])->first();
        if (isset($relation)) {
            $tenant = Tenant::find($relation->tenant_id);

            if (!$tenant) {
                return response()->json([
                    'status' => false,
                    'message' => 'Tenant not found.'
                ], 404);
            }

            // Switch to tenant DB
            tenancy()->initialize($tenant);

            $tenantUser = User::where('email', $request->email)->first();

            if (!$tenantUser || !Hash::check($request->password, $tenantUser->password)) {
                tenancy()->end();
                return response()->json([
                    'status' => false,
                    'message' => 'Invalid credentials.'
                ], 401);
            }

            if (is_null($tenantUser->email_verified_at)) {
                tenancy()->end();
                return response()->json([
                    'status' => false,
                    'message' => 'Please verify your email.'
                ], 403);
            }

            $tenantUser->tokens()->delete();
            $token = $tenantUser->createToken('auth-token')->plainTextToken;

            $tokenModel = $tenantUser->tokens()->latest()->first();
            $tokenModel->forceFill([
                'tenant_id' => $tenant->id,
            ])->save();

            $tenantUser->load('roles.permissions');

            $userData = $tenantUser->toArray();
            $userData['tenant'] = [
                'id' => $tenant->id,
                'agency_name' => $tenant->agency_name,
                'database' => $tenant->database,
            ];

            tenancy()->end();

            return response()->json([
                'status' => true,
                'message' => 'Tenant login successful',
                'user' => $userData,
                'token' => $token,
            ]);
        } else{
            return response()->json([
                'status' => false,
                'message' => 'Invalid credentials.'
            ], 401);
        }

        return response()->json([
            'status' => false,
            'message' => 'Invalid user type.'
        ], 403);
    }

    public function login(Request $request): JsonResponse
    {
        $request->validate([
            'email' => 'required|email',
            'password' => 'required',
        ]);

        
        tenancy()->end();

        $google2fa = new Google2FA();

        /*
        |--------------------------------------------------------------------------
        | 1️⃣ CENTRAL USER LOGIN
        |--------------------------------------------------------------------------
        */
        $centralUser = User::select('id', 'name', 'email', 'password', 'email_verified_at', 'user_type', 'failed_attempts', 'locked_until', 'google2fa_secret')->where('email', $request->email)->first();

        if ($centralUser) {

            // 🔐 Check Account Lock
            if ($centralUser->locked_until && now()->lessThan($centralUser->locked_until)) {
                $remainingSeconds = now()->diffInSeconds($centralUser->locked_until);
                return response()->json([
                    'message' => 'Account locked. Try again after ' . gmdate("H:i:s", $remainingSeconds)
                ], 403);
            }

            // ❌ Wrong Password
            if (!Hash::check($request->password, $centralUser->password)) {

                $centralUser->failed_attempts++;

                if ($centralUser->failed_attempts >= 3) {
                    $centralUser->locked_until = now()->addHours(24);
                    $centralUser->failed_attempts = 0;
                }

                $centralUser->save();

                return response()->json([
                    'status' => false,
                    'message' => 'Invalid Credentials.'
                ], 400);
            }

            // 📧 Email Verification
            if (!$centralUser->email_verified_at) {
                return response()->json([
                    'status' => false,
                    'message' => 'Please verify your email.'
                ], 403);
            }

            // ✅ Reset lock
            $centralUser->update([
                'failed_attempts' => 0,
                'locked_until' => null
            ]);

            // 🔐 MFA FLOW (if enabled)
            return $this->handleMfaFlow(
                $centralUser,
                'central',
                null,
                $google2fa
            );
        }

        /*
        |--------------------------------------------------------------------------
        | 2️⃣ TENANT USER LOGIN
        |--------------------------------------------------------------------------
        */
        $relation = CentralTenantTelations::where([
            'email' => $request->email,
            'status' => 'active'
        ])->first();

        if (!$relation) {
            return response()->json([
                'status' => false,
                'message' => 'Invalid credentials.'
            ], 400);
        }

        $tenant = Tenant::find($relation->tenant_id);

        if (!$tenant) {
            return response()->json([
                'status' => false,
                'message' => 'Tenant not found.'
            ], 404);
        }

        tenancy()->initialize($tenant);

        $tenantUser = User::where('email', $request->email)->first();

        if (!$tenantUser) {
            tenancy()->end();

            return response()->json([
                'status' => false,
                'message' => 'Invalid Credentials.'
            ], 400);
        }

        // 🔐 Lock Check
        if ($tenantUser->locked_until && now()->lessThan($tenantUser->locked_until)) {
            tenancy()->end();
            $remainingSeconds = now()->diffInSeconds($tenantUser->locked_until);
            return response()->json([
                'message' => 'Account locked. Try again after ' . gmdate("H:i:s", $remainingSeconds)
            ], 403);
        }

        // ❌ Wrong Password
        if (!Hash::check($request->password, $tenantUser->password)) {

            $tenantUser->failed_attempts++;

            if ($tenantUser->failed_attempts >= 3) {
                $tenantUser->locked_until = now()->addHours(24);
                $tenantUser->failed_attempts = 0;
            }

            $tenantUser->save();

            tenancy()->end();

            return response()->json([
                'status' => false,
                'message' => 'Invalid Credentials.'
            ], 400);
        }

        // 📧 Email Verification
        if (!$tenantUser->email_verified_at) {
            tenancy()->end();

            return response()->json([
                'status' => false,
                'message' => 'Please verify your email.'
            ], 403);
        }

        // ✅ Reset lock
        $tenantUser->update([
            'failed_attempts' => 0,
            'locked_until' => null
        ]);

        // 🔐 MFA FLOW
        $response = $this->handleMfaFlow(
            $tenantUser,
            'tenant',
            $tenant->id,
            $google2fa
        );

        tenancy()->end();

        return $response;
    }

    private function handleMfaFlow($user, $userType, $tenantId, $google2fa)
    {
        /*
        |--------------------------------------------------------------------------
        | FIRST TIME SETUP → GENERATE QR
        |--------------------------------------------------------------------------
        */
        if (empty($user->google2fa_secret)) {

            $secret = $google2fa->generateSecretKey();

            cache()->put('mfa_setup_'.$userType.'_'.$user->id, $secret, now()->addMinutes(10));

            $qrCodeUrl = $google2fa->getQRCodeUrl(
                config('app.name'),
                $user->email,
                $secret
            );

            $renderer = new ImageRenderer(
                new RendererStyle(200),
                new SvgImageBackEnd()
            );

            $writer = new Writer($renderer);

            return response()->json([
                'message' => "Please scan the QR code with Google Authenticator and enter the 6-digit OTP to continue.",
                'user_id' => $user->id,
                'user_type' => $userType,
                'tenant_id' => $tenantId,
                'qr_code' => base64_encode($writer->writeString($qrCodeUrl))
            ]);
        }

        /*
        |--------------------------------------------------------------------------
        | SECRET EXISTS → REQUIRE OTP
        |--------------------------------------------------------------------------
        */
        return response()->json([
            'message' => "Please open your Google Authenticator and enter the 6-digit code.",
            'user_id' => $user->id,
            'user_type' => $userType,
            'tenant_id' => $tenantId
        ]);
    }

    public function verifyMfa(Request $request)
    {
        $request->validate([
            'user_id'   => 'required',
            'otp'       => 'required|digits:6',
            'user_type' => 'required|in:central,tenant',
            'tenant_id' => 'nullable'
        ]);

        $google2fa = new Google2FA();

        /*
        |--------------------------------------------------------------------------
        | INITIALIZE TENANCY
        |--------------------------------------------------------------------------
        */
        if ($request->user_type === 'tenant') {
            $tenant = Tenant::find($request->tenant_id);

            if (!$tenant) {
                return response()->json(['message' => 'Tenant not found'], 404);
            }

            tenancy()->initialize($tenant);
        } else {
            tenancy()->end();
        }

        $user = User::find($request->user_id);

        if (!$user) {
            return response()->json(['message' => 'User not found'], 404);
        }

        /*
        |--------------------------------------------------------------------------
        | DETERMINE SECRET (SETUP OR LOGIN)
        |--------------------------------------------------------------------------
        */
        $cacheKey = 'mfa_setup_'.$request->user_type.'_'.$user->id;
        $cachedSecret = cache()->get($cacheKey);

        // Use cached secret if exists (first-time setup)
        $secret = $cachedSecret ?: $user->google2fa_secret;

        if (!$secret || strlen($secret) < 16) {
            return response()->json(['message' => 'Invalid or missing MFA secret'], 400);
        }

        /*
        |--------------------------------------------------------------------------
        | VERIFY OTP (ALLOW SMALL TIME DRIFT)
        |--------------------------------------------------------------------------
        */
        if (!$google2fa->verifyKey($secret, $request->otp, 4)) {
            return response()->json(['message' => 'Invalid OTP'], 401);
        }

        /*
        |--------------------------------------------------------------------------
        | IF FIRST TIME SETUP → SAVE SECRET
        |--------------------------------------------------------------------------
        */
        if ($cachedSecret) {
            $user->google2fa_secret = $cachedSecret; // encrypt() if you want
            $user->save();

            cache()->forget($cacheKey);
        }

        return $this->generateTokens(
            $user,
            $request->user_type,
            $request->tenant_id
        );
    }

    private function generateTokens($user, $userType, $tenantId = null)
    {
        $tokenExpireMinutes = (int) optional(Settings::where('key','access_token_expires_in_minutes')->first())->value ?? 15;
        $refreshExpireMinutes = (int) optional(Settings::where('key','refresh_token_expires_in_minutes')->first())->value ?? 120;

        $user->tokens()->delete();

        // Access Token
        $access = $user->createToken('auth-token', ['*'], now()->addMinutes($tokenExpireMinutes));
        $accessModel = $access->accessToken;
        $accessModel->token_type = 'access';
        $accessModel->mfa_verified = true;
        $accessModel->tenant_id = $tenantId;
        $accessModel->expires_at = now()->addMinutes($tokenExpireMinutes);
        $accessModel->save();

        // Refresh Token
        $refresh = $user->createToken('refresh_token', ['refresh'], now()->addMinutes($refreshExpireMinutes));
        $refreshToken = $refresh->accessToken;
        $refreshToken->token_type = 'refresh';
        $refreshToken->mfa_verified = true;
        $refreshToken->tenant_id = $tenantId;
        $refreshToken->expires_at = now()->addMinutes($refreshExpireMinutes);
        $refreshToken->save();
      
        return response()->json([
            'status' => true,
            'token' => $access->plainTextToken,
            'refresh_token' => $refresh->plainTextToken,
            'user_type' => $userType,
            'tenant_id' => $tenantId
        ]);
    }

    public function refreshToken(Request $request)
    {
        $refreshToken = $request->refresh_token;

        $token = PersonalAccessToken::findToken($refreshToken);

        if (!$token || $token->token_type !== 'refresh') {
            return response()->json(['message' => 'Invalid refresh token'], 401);
        }

        if ($token->expires_at < now()) {
            return response()->json(['message' => 'Refresh token expired'], 401);
        }

        $user = $token->tokenable;

        // Delete old access tokens
        $user->tokens()->where('token_type', 'access')->delete();

        // Create new access token
        $newAccessToken = $user->createToken(
            'access_token',
            ['*'],
            now()->addMinutes(15)
        );

        return response()->json([
            'token' => $newAccessToken->plainTextToken
        ]);
    }

    public function logout(Request $request)
    {
        $bearer = $request->bearerToken();

        if (!$bearer) {
            return response()->json(['message' => 'Token not provided'], 401);
        }

        // Try to find token in current context (whether central or tenant)
        $token = PersonalAccessToken::findToken($bearer);

        if ($token) {
            $token->delete();
            return response()->json(['message' => 'Logged out successfully']);
        }

        // If not found in current context, end tenancy and try central
        tenancy()->end();
        $token = PersonalAccessToken::findToken($bearer);

        if ($token) {
            $token->delete();
            return response()->json(['message' => 'Logged out successfully']);
        }

        return response()->json(['message' => 'Token not found or invalid'], 401);
    }

    public function forgotPassword(Request $request): JsonResponse
    {
        // Check in central users table
        $user = User::where('email', $request->email)->first();

        // If not found, check relation table (agent / tenant user)
        if (!$user) {
            $relation = CentralTenantTelations::where('email', $request->email)->first();

            if (!$relation) {
                return response()->json([
                    'status' => false,
                    'message' => 'Email not found.'
                ], 404);
            }
        }

        // Generate reset token
        $plainToken = Str::random(64);

        DB::table('password_reset_tokens')->updateOrInsert(
            ['email' => $request->email],
            [
                'token' => Hash::make($plainToken),
                'created_at' => now()
            ]
        );

        // Create reset URL (frontend page)
        $resetUrl = config('app.frontend_url') .
            "/reset-password?token={$plainToken}&email=" . urlencode($request->email);

        // Send mail
        Mail::raw("Click the link to reset your password: $resetUrl", function ($message) use ($request) {
            $message->to($request->email)
                    ->subject('Reset Password Request');
        });

        return response()->json([
            'status' => true,
            'message' => 'Password reset link sent to your email.'
        ]);
    }

    public function resetPassword(Request $request): JsonResponse
    {
        $request->validate([
            'token' => 'required',
            'email' => 'required|email',
            'password' => 'required|min:6',
        ]);

        // Find token record
        $record = DB::table('password_reset_tokens')
            ->where('email', $request->email)
            ->first();

        if (!$record) {
            return response()->json([
                'status' => false,
                'message' => 'Invalid or expired token.'
            ], 400);
        }

        // Check token match
        if (!Hash::check($request->token, $record->token)) {
            return response()->json([
                'status' => false,
                'message' => 'Invalid or expired token.'
            ], 400);
        }

        // Check token expiry (60 minutes)
        if (now()->diffInMinutes($record->created_at) > 60) {
            return response()->json([
                'status' => false,
                'message' => 'Token expired.'
            ], 400);
        }

        // Try updating central user first
        $user = User::where('email', $request->email)->first();

        if ($user) {
            $user->password = Hash::make($request->password);
            $user->setRememberToken(Str::random(60));
            $user->save();
        } else {
            // If not central, update tenant user
            $relation = CentralTenantTelations::where('email', $request->email)->first();

            if (!$relation) {
                return response()->json([
                    'status' => false,
                    'message' => 'User not found.'
                ], 404);
            }

            // Switch tenant DB connection
            tenancy()->initialize($relation->tenant_id);

            $tenantUser = User::where('email', $request->email)->first();

            if (!$tenantUser) {
                return response()->json([
                    'status' => false,
                    'message' => 'User not found in tenant.'
                ], 404);
            }

            $tenantUser->password = Hash::make($request->password);
            $tenantUser->setRememberToken(Str::random(60));
            $tenantUser->save();

            tenancy()->end();
        }

        // Delete token after use
        DB::table('password_reset_tokens')
            ->where('email', $request->email)
            ->delete();

        return response()->json([
            'status' => true,
            'message' => 'Password has been reset successfully.'
        ]);
    }

    public function userDetails(Request $request): JsonResponse
    {   
        $user = User::select('id', 'name', 'email', 'user_type')->find($request->user()->id);
        //$user->load('roles.permissions','tenant');

        return response()->json(['type' => 'central', 'user' => $user]);
    }

   public function updateProfile(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'name' => 'required|string|max:255',
            'agency_name' => 'nullable|string|max:255',
        ]);
 
        if ($validator->fails()) {
            return response()->json(['errors' => $validator->errors()], 422);
        }
 
        $token = PersonalAccessToken::findToken($request->bearerToken());
 
        if (!$token) {
            return response()->json(['message' => 'Unauthenticated'], 401);
        }
 
        if ($token->tenant_id) {
            tenancy()->initialize($token->tenant_id);
        }
 
        $user = User::find($token->tokenable_id);
 
        if (!$user) {
            return response()->json(['message' => 'User not found'], 404);
        }
 
        $updateData = [
            'name' => $request->name,
        ];
 
        $user->update($updateData);
 
        if ($request->filled('agency_name') && $user->tenant_id) {
            $tenant = Tenant::find($user->tenant_id);
            if ($tenant) {
                $tenant->update([
                    'agency_name' => $request->agency_name,
                ]);
            }
        }
 
        return response()->json([
            'status' => true,
            'message' => 'Profile updated successfully.',
        ], 200);
    }

    public function changePassword(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'current_password' => 'required|string',
            'new_password' => 'required|confirmed',
        ]);
 
        if ($validator->fails()) {
            return response()->json(['errors' => $validator->errors()], 422);
        }
 
        $token = PersonalAccessToken::findToken($request->bearerToken());
 
        if (!$token) {
            return response()->json(['message' => 'Unauthenticated'], 401);
        }
 
        $user = User::find($token->tokenable_id);
 
        if (!$user) {
            return response()->json(['message' => 'User not found'], 404);
        }
 
        if (!Hash::check($request->current_password, $user->password)) {
            return response()->json(['message' => 'Current password is incorrect'], 403);
        }
 
        $user->update([
            'password' => Hash::make($request->new_password),
        ]);
 
        return response()->json([
            'status' => true,
            'message' => 'Password changed successfully.',
        ], 200);
    }

}