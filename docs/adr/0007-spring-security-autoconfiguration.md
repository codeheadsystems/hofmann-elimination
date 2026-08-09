# 7. `HofmannSecurityConfig` is an `@AutoConfiguration`, not an imported `@Configuration`

- **Status:** Accepted (2026-08-08). In force.
- **Decided in:** `052499a` (PR #95)
- **Implements:** [`HofmannSecurityConfig`](../../hofmann-springboot/src/main/java/com/codeheadsystems/hofmann/springboot/security/HofmannSecurityConfig.java),
  `AutoConfiguration.imports`
- **Related:** [ADR-0005](0005-closed-contexts-refuse-use.md), [ADR-0008](0008-sealed-opaque-package.md)
  — three cases of a documented guarantee that nothing enforced.

## Context

`HofmannSecurityConfig` documents an escape hatch: an application defining its own
`SecurityFilterChain` gets the library's to back off, via `@ConditionalOnMissingBean`. For a
consumer whose component scan reached `com.codeheadsystems.hofmann.springboot`, it did not work —
the application failed to start with `UnreachableFilterChainException`.

The trigger is component scanning. As a plain `@Configuration` in a scannable package the class
could be picked up twice: once through the auto-configuration import, and again as an ordinary
user configuration. Scanned in, it loses the deferred phase that guarantees auto-configuration is
read last, so the condition really did run first, find nothing, and register the chain anyway.

Not hypothetical: `IntegrationTestApplication` in this repository scans that package explicitly,
commented as picking up "controllers and security config". That is in-repo documented practice, so
a consumer who copied it hit this.

## Decision

Make it an `@AutoConfiguration` listed in `AutoConfiguration.imports`. Boot's
`AutoConfigurationExcludeFilter` keeps auto-configuration classes out of component scans by
construction, so the double pickup becomes impossible rather than unlikely.

Three attributes are load-bearing rather than decorative:

- `after = HofmannAutoConfiguration.class` — `@ConditionalOnBean` can only see beans an earlier
  auto-configuration has already contributed, and `JwtManager` comes from there.
- `before = ServletWebSecurityAutoConfiguration.class` — without it, winning against Boot's own
  default chain was decided by alphabetical class name, since `com.codeheadsystems` sorts before
  `org.springframework`. Deliberate beats lucky.
- `@ConditionalOnBean(JwtManager.class)` — makes the two halves of the library leave together.

## Alternatives rejected

- **Keep it `@Imported` and document "do not scan our package".** A rule the repository's own
  example application already broke.
- **Scope the chain with `securityMatcher`.** Rejected as the shipped default: the chain is
  unscoped by design so the JWT filter authenticates the consumer's own endpoints, which is the
  point of the library.

## Consequences

- **Taking over means taking over completely.** The condition triggers on the presence of any
  chain, not on what it matches, so a chain scoped with `securityMatcher("/api/**")` still
  displaces this one — and everything outside that matcher is then served with no chain at all.
  That is a fail-open gap in the consumer's application, called out in the class javadoc: end your
  chain with `anyRequest().authenticated()` rather than scoping it.
- Adopting the default chain means every URL requires a Hofmann JWT unless explicitly permitted.
  `/opaque/**` and `/oprf/**` must stay permitted — the handshake is how a caller obtains a token,
  so requiring one to reach it would be circular.

## Superseded analyses

- **"`@ConditionalOnMissingBean` is evaluated before the application's beans for every consumer."**
  My first explanation, and wrong. A reviewer disproved it by booting a real application: a
  consumer who does not scan the library's package backed off correctly all along. The real
  trigger is component scanning, and the corrected explanation makes a prediction the original did
  not — reverting the move fails the scanning tests and leaves the non-scanning ones passing,
  which is what the controls now assert.
- **"The old `ApplicationContextRunner` test was worse than absent."** Over-claimed. It was
  incomplete, not false: it exercised the non-scanning path and told the truth about it while
  saying nothing about the scanning one. Deleting it removed the only coverage of the case that
  was never broken. `NonScanningConsumerBackOffTest` restores that path in a real context, in a
  sibling package so its applications genuinely do not scan the library.
- **The move introduced a regression, caught in review rather than by me.** While the security
  config was `@Imported`, excluding `HofmannAutoConfiguration` via `spring.autoconfigure.exclude`
  took both halves out together. Standing alone it stayed loaded and reached for a `JwtManager`
  the exclusion had just removed — so asking for the library to be *off* produced
  `NoSuchBeanDefinitionException` at startup.
- **One of the new tests was vacuous, and its own control caught it.** The exclusion tests ran as
  `WebApplicationType.NONE`, where `@ConditionalOnWebApplication(SERVLET)` means the configuration
  never loads at all — so they passed with `@ConditionalOnBean` deleted. They run as `SERVLET`
  now and fail without it.
