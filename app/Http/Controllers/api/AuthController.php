<?php

namespace App\Http\Controllers\api;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Cookie;
use Illuminate\Support\Facades\Hash;
use Symfony\Component\HttpFoundation\Response;

class AuthController extends Controller
{
    public function register(Request $request)
    {
        //validacion de datos
        $request->validate([
            'name' => 'required',
            'email' => 'required|email|unique:users',
            'password' => 'required|confirmed'
        ]);
        //registro de los datos
        $user = new User();
        $user->name = $request->name;
        $user->email = $request->email;
        $user->password = Hash::make($request->password);
        $user->save();
        //respuesta
        // return response() ->json([
        //     "menssage" => "metodo register ok"
        // ]);
        return response($user, Response::HTTP_CREATED);
    }
    public function login(Request $request)
    {
        $credenciales = $request->validate([
            'email' => 'required|email',
            'password' => 'required'
        ]);
        if (Auth::attempt($credenciales)) {
            $user = Auth::user();
            $token = $user->CreateToken('Token')->plainTextToken;
            $cookie = cookie('cookie_token', $token, 6 * 24);
            return response(["token" => $token], response::HTTP_OK)->withoutCookie($cookie);
        } else {
            return response(["message" => "Credenciales invalidas"], Response::HTTP_UNAUTHORIZED);
        }
    }
    public function userprofile(Request $request)
    {
        return response()->json([
            "messange" => "Datos de usuario",
            "userData" => auth()->user()
        ], Response::HTTP_OK);
    }
    public function logout(Request $request)
    {
        if ($request->hasCookie('cookie_token')) {
            $user = Auth::user()->tokens()->delete();
            $cookie = Cookie::forget('cookie_token');
            return response(["message" => "Cierre de sesion exitoso"], Response::HTTP_OK)->withCookie($cookie);
        } else {
            return response(["message" => "No se encontró la cookie de sesion"], Response::HTTP_NOT_FOUND);
        }
    }
    public function AllUsers(Request $request)
    {
    }
}
