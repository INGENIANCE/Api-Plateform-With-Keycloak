<?php

namespace App\Security;

use KnpU\OAuth2ClientBundle\Client\ClientRegistry;
use KnpU\OAuth2ClientBundle\Security\Authenticator\SocialAuthenticator;
use League\OAuth2\Client\Provider\Exception\IdentityProviderException;
use League\OAuth2\Client\Token\AccessToken;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\Session\SessionInterface;
use Symfony\Component\HttpKernel\Exception\UnauthorizedHttpException;
use Symfony\Component\Routing\RouterInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\User\UserProviderInterface;

class KeycloakAuthenticator extends SocialAuthenticator
{
    private $clientRegistry;
    private $router;
    private $session;

    public function __construct(ClientRegistry $clientRegistry, RouterInterface $router, SessionInterface $session)
    {
        $this->clientRegistry = $clientRegistry;
        $this->router = $router;
        $this->session = $session;
    }

    public function start(Request $request, AuthenticationException $authException = null)
    {
        $path = $request->getPathInfo();
        $this->session->set("nextPath", $path);

        if ($request->headers->get("Authorization") === null) {
            return new RedirectResponse(
                '/connect/',
                Response::HTTP_TEMPORARY_REDIRECT
            );
        }

        $targetUrl = $this->router->generate('connect_check', ["Authorization" => $request->headers->get("Authorization")]);
        return new RedirectResponse(
            $targetUrl,
            Response::HTTP_TEMPORARY_REDIRECT
        );
    }

    public function supports(Request $request)
    {
        return $request->attributes->get('_route') === 'connect_check';
    }

    public function getCredentials(Request $request)
    {
        if ($request->headers->get("Authorization") === null) {
            return $this->fetchAccessToken($this->getClient());
        }

        $token = str_replace("Bearer ", "", $request->headers->get("Authorization"));
        return new AccessToken(["access_token" => $token, "token_type" => "bearer"]);
    }

    public function getUser($credentials, UserProviderInterface $userProvider)
    {
        try {
            return $userProvider->loadUserByUsername($this->getClient()->fetchUserFromToken($credentials)->getId());
        } catch (IdentityProviderException $e) {
            throw new UnauthorizedHttpException($e->getMessage());
        }
    }

    private function getClient()
    {
        return $this->clientRegistry->getClient('keycloak');
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception)
    {
        $message = strtr($exception->getMessageKey(), $exception->getMessageData());
        return new Response($message, Response::HTTP_FORBIDDEN);
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $providerKey)
    {
        if ($this->session->has("nextPath")) {
            $path = $this->session->get("nextPath");
            $this->session->remove("nextPath");
            return new RedirectResponse($path, 307);
        }

        return new RedirectResponse("/");
    }
}
