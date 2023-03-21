<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Response;
use Laravel\Passport\TokenRepository;
use Symfony\Component\HttpKernel\Exception\BadRequestHttpException;


class AuthController extends Controller
{
    public function register(Request $request)

    {
            $user = User::create([
                'name'     => $request->name,
                'email'    => $request->email,
                'password' => $request->password,
            ]);

            return $user;
    }

    public function login(Request $request)
    {
        $user = User::where('email', $request->email)->first();

        if (!$user) {
            return 'Bad Credentials' ;
        }

        $user->validateForPassportPasswordGrant($request->password);

        $user['token'] = $user->createToken('passport_token')->accessToken;

        return $user;
    }

    public function logout()
    {
        $token = auth()->user()->token();

        $tokenReposetory = app(TokenRepository::class);
        $tokenReposetory->revokeAccessToken($token->id);
        return  "logout success" ;
    }


}
