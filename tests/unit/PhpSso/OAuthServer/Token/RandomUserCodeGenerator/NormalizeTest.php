<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Tests\Unit\Token\RandomUserCodeGenerator;

use PHPUnit\Framework\Attributes\CoversMethod;
use PHPUnit\Framework\TestCase;
use PhpSso\OAuthServer\Token\RandomUserCodeGenerator;

#[CoversMethod(RandomUserCodeGenerator::class, 'normalize')]
final class NormalizeTest extends TestCase
{
    public function testCaseSpacesAndDashesDoNotMatter(): void
    {
        // Act
        $code = RandomUserCodeGenerator::normalize(' wdjb - mjht ');

        // Assert
        self::assertSame('WDJBMJHT', $code);
    }
}
