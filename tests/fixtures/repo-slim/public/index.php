<?php
$app->get('/api/admin', function ($req, $res) { return $res; })->add(new AuthMiddleware());
$app->post('/api/report', function ($req, $res) {
    mail($req->getParsedBody()['email'], 'report', '');
    return $res;
});
