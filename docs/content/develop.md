---
title: Develop
weight: 8
lead: Run the checks and follow the test conventions.
---

```bash
composer install
composer check      # PHPStan (level max, strict rules, no baseline) and PHPUnit
```

Tests follow Arrange, Act, Assert, one file per method:
`tests/unit/PhpSso/OAuthServer/{Namespace}/{Class}/{Method}Test.php`.
