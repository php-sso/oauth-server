<?php

declare(strict_types=1);

namespace PhpSso\OAuthServer\Tests\Unit\Token\RandomUserCodeGenerator;

use PHPUnit\Framework\Attributes\CoversMethod;
use PHPUnit\Framework\TestCase;
use PhpSso\OAuthServer\Token\RandomUserCodeGenerator;

#[CoversMethod(RandomUserCodeGenerator::class, 'format')]
final class FormatTest extends TestCase
{
    public function testItShowsTheCodeInTwoGroupsOfFour(): void
    {
        // Act
        $shown = RandomUserCodeGenerator::format('WDJBMJHT');

        // Assert
        self::assertSame('WDJB-MJHT', $shown);
    }
}
