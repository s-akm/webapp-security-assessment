<?php
// ガードあり（コンストラクタでミドルウェア）
namespace App\Http\Controllers;
class AdminController extends Controller
{
    public function __construct() { $this->middleware('auth'); }
    public function index() { return User::select('id')->get(); }
}
