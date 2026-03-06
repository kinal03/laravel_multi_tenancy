<?php
 
namespace Database\Seeders;
 
use App\Models\User,App\Models\Settings;
// use Illuminate\Database\Console\Seeds\WithoutModelEvents;
use Illuminate\Database\Seeder;
use Illuminate\Support\Facades\Hash;
use Spatie\Permission\Models\Role;
use Spatie\Permission\Models\Permission;
 
 
class DatabaseSeeder extends Seeder
{
    /**
     * Seed the application's database.
     */
    public function run(): void
    {
         /** -------------------------------------------------
         * ALWAYS USE CENTRAL DB
         * -------------------------------------------------*/
        config(['database.default' => 'mysql']);
 
        /** -------------------------------------------------
         * GET ALL PERMISSIONS FROM DB
         * (No static permissions now)
         * -------------------------------------------------*/
        // $allPermissions = Permission::where('guard_name', 'sanctum')->get();
 
        // if ($allPermissions->count() === 0) {
        //     $this->command->warn('⚠ No permissions found in DB. Seeder stopped.');
        //     return;
        // }
 
        $allPermissions = collect([
            'role-access',
            'role-create',
            'role-edit',
            'role-show',
            'role-delete',
            'permission-access',
            'permission-create',
            'permission-edit',
            'permission-show',
            'permission-delete',
            'settings-access',
            'settings-create',
            'settings-edit',
            'settings-show',
            'settings-delete',
            'invitation-access',
            'admin-access',
            'admin-create',
            'admin-edit',
            'admin-show',
            'admin-delete',
            'agency-access',
            'agency-create',
            'agency-edit',
            'agency-show',
            'agency-delete',
            'agent-access',
            'agent-create',
            'agent-edit',
            'agent-show',
            'agent-delete',
            'tenant-role-access',
            'tenant-role-create',
            'tenant-role-edit',
            'tenant-role-show',
            'tenant-role-delete',
            'tenant-permission-access',
            'tenant-permission-create',
            'tenant-permission-edit',
            'tenant-permission-show',
            'tenant-permission-delete',
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
            'name' => 'Super Admin',
            'guard_name' => 'sanctum',
        ]);
 
        /** -------------------------------------------------
         * GIVE ALL PERMISSIONS TO SUPER ADMIN
         * -------------------------------------------------*/
        $superAdminRole->syncPermissions($allPermissions);
 
        /** -------------------------------------------------
         * CREATE OR GET SUPER ADMIN USER
         * -------------------------------------------------*/
        $superAdmin = User::firstOrCreate(
            ['email' => 'superadmin@gmail.com'],
            [
                'name' => 'Super Admin',
                'password' => Hash::make('password123'),
                'email_verified_at' => now(),
                'user_type' => 'super_admin',
            ]
        );
 
        Settings::insert([
            ['key' => 'expired_link_duration', 'value' => '2'],
            ['key' => 'access_token_expires_in_minutes', 'value' => '1'],
            ['key' => 'refresh_token_expires_in_minutes', 'value' => '120'],  
            ['key' => 'login_attempt_seconds', 'value' => '6'],   // gap in seconds
            ['key' => 'login_attempt_minute', 'value' => '5'],     // per minute
            ['key' => 'login_attempt_hour', 'value' => '30'],      // per hour
        ]);
 
        /** -------------------------------------------------
         * ASSIGN ROLE TO USER
         * -------------------------------------------------*/
        if (!$superAdmin->hasRole('Super Admin')) {
            $superAdmin->assignRole($superAdminRole);
        }
 
        $this->command->info('Super Admin created with ALL permissions');
    }
}
 