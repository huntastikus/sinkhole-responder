# Changelog

## [0.3.0](https://github.com/huntastikus/sinkhole-responder/compare/v0.2.2...v0.3.0) (2026-07-23)


### Features

* **admin:** backups, password change, read-only API token, rulepack preview ([8818dcd](https://github.com/huntastikus/sinkhole-responder/commit/8818dcd78895bf592aabe162daad06acb680460e))
* **httpserver:** apply rate-limit changes live without restart ([fd72e1d](https://github.com/huntastikus/sinkhole-responder/commit/fd72e1d86638a20802e8abdc74dc358126b89bce))
* **mgmt:** count and expose per-rule hits ([b30c133](https://github.com/huntastikus/sinkhole-responder/commit/b30c1339990014e16313c030a339c57727e60e6c))
* **mgmt:** persist metrics and history across restarts ([6c5680e](https://github.com/huntastikus/sinkhole-responder/commit/6c5680eb85f636e8b307187fc3b79c56e2146a0b))
* per-rule stats, metrics persistence, live rate limits, backups, password change, API token, rulepack preview, config file-watch ([#12](https://github.com/huntastikus/sinkhole-responder/issues/12)) ([8be6d2f](https://github.com/huntastikus/sinkhole-responder/commit/8be6d2f7e61423aeb756fac993838ef9cc9e43e8))
* reload configuration when the file changes on disk ([2460b10](https://github.com/huntastikus/sinkhole-responder/commit/2460b10a659220d24477b4ff069b30a330b15981))
* **ui:** dashboard breakdown, unsaved-change guards, searchable logs, import confirm, polish ([#9](https://github.com/huntastikus/sinkhole-responder/issues/9)) ([374f303](https://github.com/huntastikus/sinkhole-responder/commit/374f303dba8551c1ffa930bd93fbc286c8142355))
* **ui:** dashboard kind/status breakdown, 3h range, leaf-cache trend ([4fa2950](https://github.com/huntastikus/sinkhole-responder/commit/4fa29504a1a7c4d7b674f82b64a5324e49cd726c))
* **ui:** fingerprint copy, rules cross-links, theme flash fix, dedicated reorder ([eadae56](https://github.com/huntastikus/sinkhole-responder/commit/eadae56dff109b09aa3ce920ee9f51164872f0c7))
* **ui:** searchable, flicker-free, downloadable logs ([15f1008](https://github.com/huntastikus/sinkhole-responder/commit/15f10085b86e209d93bde2d0669785d85d39e6c3))
* **ui:** warn before leaving config or rules with unsaved changes ([23d63ac](https://github.com/huntastikus/sinkhole-responder/commit/23d63acb513ead7aa17d48f87660c80955552c42))


### Bug Fixes

* **admin:** address functionality review nits ([a128fa2](https://github.com/huntastikus/sinkhole-responder/commit/a128fa2db3628a9f1349ec4ae1adda1b470dbb23))
* **admin:** address TLS health review findings ([8212d41](https://github.com/huntastikus/sinkhole-responder/commit/8212d41b18a93c6001f2bbe57a75f014952f4531))
* **admin:** inspect certificate files and expiry in TLS health check ([0e67046](https://github.com/huntastikus/sinkhole-responder/commit/0e670464267b67aac15e9fd2f5f274e5f6a19a6f))
* **admin:** inspect certificate files and expiry in TLS health check ([#11](https://github.com/huntastikus/sinkhole-responder/issues/11)) ([f5f829f](https://github.com/huntastikus/sinkhole-responder/commit/f5f829f0ea731e5b0017d34b8126749a8bde5fb4))
* **rules:** recursive ** glob matching for host_glob/path_glob ([#10](https://github.com/huntastikus/sinkhole-responder/issues/10)) ([2a11dbb](https://github.com/huntastikus/sinkhole-responder/commit/2a11dbb48588944d4a49d3fbd65fcd34e6594928))
* **rules:** support recursive ** segments in host_glob and path_glob ([c015d83](https://github.com/huntastikus/sinkhole-responder/commit/c015d8363d813271b618fabcbc9e5c4bc578e018))
* **ui:** address UI review findings ([1d1c44a](https://github.com/huntastikus/sinkhole-responder/commit/1d1c44a5ef62779abcd67c4f35ce19932efc2e1e))


### Refactors

* **rules:** address glob review findings ([120b9e4](https://github.com/huntastikus/sinkhole-responder/commit/120b9e4d0444d38081ae95ffb0413ac71992a9af))

## [0.2.2](https://github.com/huntastikus/sinkhole-responder/compare/v0.2.1...v0.2.2) (2026-07-21)


### Documentation

* overhaul project and Docker Hub documentation ([#6](https://github.com/huntastikus/sinkhole-responder/issues/6)) ([f3116d4](https://github.com/huntastikus/sinkhole-responder/commit/f3116d465fe296908fc2e5d58ed438340db6b60a))
* reorganize project documentation ([41d4258](https://github.com/huntastikus/sinkhole-responder/commit/41d42589cb2c286fd4ae477da438094853df601a))

## [0.2.1](https://github.com/huntastikus/sinkhole-responder/compare/v0.2.0...v0.2.1) (2026-07-21)


### Bug Fixes

* improve Docker release metadata ([a26c76a](https://github.com/huntastikus/sinkhole-responder/commit/a26c76a3e01f065892208e1619bd9840baccc0dc))
* improve Docker release metadata ([#5](https://github.com/huntastikus/sinkhole-responder/issues/5)) ([50ab29e](https://github.com/huntastikus/sinkhole-responder/commit/50ab29eee53bd6266076b7a2f0d921d9de5160fc))

## [0.2.0](https://github.com/huntastikus/sinkhole-responder/compare/v0.1.0...v0.2.0) (2026-07-21)


### Features

* polish admin deployment and add secure request logging ([4c9fe4b](https://github.com/huntastikus/sinkhole-responder/commit/4c9fe4bb5696c70d828af80d3bcf01ec0dfe3ffd))

## 0.1.0 (2026-07-21)


### Features

* add RC release pipeline ([97d0c31](https://github.com/huntastikus/sinkhole-responder/commit/97d0c313a6cd6d342c3f98bd5b631004b7aac609))
* add RC release pipeline and version display ([a66d36c](https://github.com/huntastikus/sinkhole-responder/commit/a66d36c146d3f0b9ff6523e2d419e49f430ff986))
* show version in admin UI ([076afec](https://github.com/huntastikus/sinkhole-responder/commit/076afec52004e2447eba1f61d887cf1404ed6d73))
