import Route from '@ioc:Adonis/Core/Route';

Route.get('/api/admin', 'AdminController.index').middleware('auth');
Route.post('/api/report', 'ReportController.store');
