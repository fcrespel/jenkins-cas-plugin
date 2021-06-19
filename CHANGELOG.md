# Changelog

## [Unreleased]

- Fixed security issue (SECURITY-2387).

## [1.6.0] - 2021-02-18

- Added option to customize validation URL parameters in advanced protocol configuration.
- Allow using `{{attribute}}` placeholders in Full Name and Email Attribute configuration (e.g. `{{firstName}} {{lastName}}` or `{{uid}}@example.com`).
- Fixed handling of empty attributes.

## [1.5.0] - 2020-11-22

- Compatibility with Jenkins 2.266 and higher (replacement of Acegi Security with Spring Security, see [JEP-227](https://github.com/jenkinsci/jep/tree/master/jep/227)).
- Incompatibility with Jenkins 2.265 and lower (for the reason above), please make sure to upgrade CAS plugin and Jenkins together.
- Added support for CAS 3.0 JSON protocol format.
- Added option to control redirection to CAS after logging out of Jenkins.

## [1.4.3] - 2019-01-21

- Fixed login redirect loop caused by changes in Jenkins 2.160 and 2.150.2 LTS (SECURITY-901, see [2019-01-16 security advisory](https://jenkins.io/security/advisory/2019-01-16/#SECURITY-901)).

## [1.4.2] - 2018-06-04

- Fixed security issue (SECURITY-809, see [2018-06-04 security advisory](https://jenkins.io/security/advisory/2018-06-04/))

## [1.4.1] - 2017-10-01

- Fixed NullPointerException in SessionUrlAuthenticationSuccessHandler, that could occur when coming back from CAS on some servlet containers (JENKINS-46993).
- Fixed NullPointerException in Cas10Protocol, when using an empty Groovy role parsing script (JENKINS-45441).

## [1.4.0] - 2017-05-09

- Fixed security issues related to Groovy script execution in CAS Protocol 1.0 configuration (SECURITY-488, see [2017-04-10 security advisory](https://jenkins.io/security/advisory/2017-04-10/#cas-plugin)).

## [1.3.0] - 2016-10-19

- Updated CAS client version to 3.4.1 with less dependencies and support for CAS Protocol 3.0.
- Added CAS REST API support to authenticate Jenkins API calls with real username/password (thanks to Sebastian Sdorra).
- Bumped minimum Jenkins version to 1.625.3 (and require Java 7).
- Restored compatibility with Jenkins version 2.19.1 when using SAML 1.1 (missing dependency no longer required).

## [1.2.0] - 2015-09-13

- Updated spring-security and CAS client versions with improved robustness and compatibility (thanks to Waldemar Biller).
- Improved detection of Jenkins root URL.
- Fixed usage of forceRenewal parameter in the ticket validator.

## [1.1.2] - 2014-06-02

- Better handling of multi-valued attributes during Jenkins user creation/update (thanks to Maxime Besson).
- Changed 'Try again' link in failed login page to be relative instead of absolute (fixes issue when Jenkins is run from sub-uri).

## [1.1.1] - 2012-11-10

- Redirect to origin URL after authentication (instead of always showing Jenkins home page).
- Show custom error page with proper "Try again" link in case of login failure (e.g. due to an invalid ticket).
- Removed unused AspectJ JARs, reducing the overall plugin size (thanks to Jozef Kotlar).

## [1.1.0] - 2012-09-07

- Support for CAS 2.0 Proxy Tickets, allowing external applications already secured with CAS to authenticate in Jenkins without requiring user input or password.

## [1.0.0] - 2012-09-05

- Initial release of the new **CAS Plugin**
- Multiple protocols support: CAS 1.0, CAS 2.0, SAML 1.1
- Custom CAS 1.0 response parsing support
- CAS 2.0 and SAML 1.1 attributes support
- Single Sign-Out support
- Jenkins API Token support (no conflict)

[Unreleased]: https://github.com/jenkinsci/cas-plugin/compare/cas-plugin-1.6.0...HEAD
[1.6.0]: https://github.com/jenkinsci/cas-plugin/compare/cas-plugin-1.5.0...cas-plugin-1.6.0
[1.5.0]: https://github.com/jenkinsci/cas-plugin/compare/cas-plugin-1.4.3...cas-plugin-1.5.0
[1.4.3]: https://github.com/jenkinsci/cas-plugin/compare/cas-plugin-1.4.2...cas-plugin-1.4.3
[1.4.2]: https://github.com/jenkinsci/cas-plugin/compare/cas-plugin-1.4.1...cas-plugin-1.4.2
[1.4.1]: https://github.com/jenkinsci/cas-plugin/compare/cas-plugin-1.4.0...cas-plugin-1.4.1
[1.4.0]: https://github.com/jenkinsci/cas-plugin/compare/cas-plugin-1.3.0...cas-plugin-1.4.0
[1.3.0]: https://github.com/jenkinsci/cas-plugin/compare/cas-plugin-1.2.0...cas-plugin-1.3.0
[1.2.0]: https://github.com/jenkinsci/cas-plugin/compare/cas-plugin-1.1.2...cas-plugin-1.2.0
[1.1.2]: https://github.com/jenkinsci/cas-plugin/compare/cas-plugin-1.1.1...cas-plugin-1.1.2
[1.1.1]: https://github.com/jenkinsci/cas-plugin/compare/cas-plugin-1.1.0...cas-plugin-1.1.1
[1.1.0]: https://github.com/jenkinsci/cas-plugin/compare/cas-plugin-1.0.0...cas-plugin-1.1.0
[1.0.0]: https://github.com/jenkinsci/cas-plugin/releases/tag/cas-plugin-1.0.0
