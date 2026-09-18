<?php
namespace App\Controller;

class ReportController extends AbstractController
{
    #[Route('/api/report', methods: ['POST'])]
    public function create(Request $request): JsonResponse
    {
        $this->conn->executeQuery("select * from users where id = " . $request->get('id'));
        return $this->json(['ok' => true]);
    }
}
