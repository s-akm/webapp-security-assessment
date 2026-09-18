<?php
Route::middleware('auth:sanctum')->get('/me', [UserController::class, 'me']);
Route::post('/report', [ReportController::class, 'store']);
