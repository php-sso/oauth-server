<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Registration;

/**
 * Decides, per registrar (the client whose access token registers other clients), whether it may register and what
 * the clients it registers may get. Optional: without one, every holder of the registration scope may register and
 * {@see RegistrationConfig} sets the limits for all.
 */
interface RegistrarPolicy
{
    /** Whether this client may register apps right now. Checked on every registration, so taking the right away works at once, even for tokens already issued. */
    public function mayRegister(string $registrarClientId): bool;

    /**
     * The scopes the apps this registrar registers may ask for, or null for what {@see RegistrationConfig::$allowedScopes} says.
     * Also applied when such an app updates itself later. The registration scope itself is never allowed.
     *
     * @return list<string>|null
     */
    public function allowedScopes(string $registrarClientId): ?array;

    /** Whether any client may register at all, so that discovery only advertises the endpoint when it can be used. */
    public function anyRegistrar(): bool;
}
