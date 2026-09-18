<?php
namespace App\Controller;

use Symfony\Component\Security\Http\Attribute\IsGranted;

class AdminController extends AbstractController
{
    #[IsGranted('ROLE_ADMIN')]
    #[Route('/api/admin', methods: ['GET'])]
    public function index(): JsonResponse { return $this->json([]); }
}
