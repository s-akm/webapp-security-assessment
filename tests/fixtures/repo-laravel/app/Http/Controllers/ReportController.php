<?php
// ガードなし。生 SQL の組み立てもある
namespace App\Http\Controllers;
class ReportController extends Controller
{
    public function store(Request $request)
    {
        DB::select("select * from users where id = " . $request->id);
        Mail::to($request->email)->send(new ReportMail());
        return response()->json(['ok' => true]);
    }
}
