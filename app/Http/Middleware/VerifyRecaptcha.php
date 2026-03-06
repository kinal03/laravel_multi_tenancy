<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;
use Illuminate\Support\Facades\Http;

class VerifyRecaptcha
{
    public function handle(Request $request, Closure $next): Response
    {
        // 1️⃣ Check if token exists
        if (!$request->filled('recaptcha_token')) {
            return response()->json([
                'status' => false,
                'message' => 'Captcha token missing.'
            ], 422);
        }

        try {

            // 2️⃣ Verify with Google
            $response = Http::asForm()
                ->timeout(10) // prevent hanging
                ->post('https://www.google.com/recaptcha/api/siteverify', [
                    'secret'   => env('RECAPTCHA_SECRET'),
                    'response' => $request->recaptcha_token,
                    'remoteip' => $request->ip(),
                ]);

            if (!$response->successful()) {
                return response()->json([
                    'status' => false,
                    'message' => 'Captcha verification server error.'
                ], 500);
            }

            $recaptcha = $response->json();

            // 3️⃣ Check success
            if (!isset($recaptcha['success']) || !$recaptcha['success']) {
                return response()->json([
                    'status' => false,
                    'message' => 'Captcha verification failed.',
                    'errors'  => $recaptcha['error-codes'] ?? []
                ], 422);
            }

        } catch (\Exception $e) {

            return response()->json([
                'status' => false,
                'message' => 'Captcha verification error.',
            ], 500);
        }

        return $next($request);
    }
}