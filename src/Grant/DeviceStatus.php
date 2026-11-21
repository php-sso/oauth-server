<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Grant;

enum DeviceStatus: string
{
    case Pending = 'pending';
    case Approved = 'approved';
    case Denied = 'denied';
}
