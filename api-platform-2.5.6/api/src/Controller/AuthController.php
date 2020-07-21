<?php

namespace App\Controller;

use KnpU\OAuth2ClientBundle\Client\ClientRegistry;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\Routing\Annotation\Route;

class AuthController extends AbstractController
{
    /**
     * @Route("/connect", name="connect_start")
     */
    public function connectAction(ClientRegistry $clientRegistry) {
        return $clientRegistry
            ->getClient('keycloak')
            ->redirect(['offline_access']);
    }

    /**
     * @Route("/connect/check", name="connect_check")
     */
    public function connectCheckAction() {}

    /**
     * @Route("/logout", name="logout")
     */
    public function logoutAction() {}
}
