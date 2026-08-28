# Changelog

## 1.0.0 (2026-08-28)


### Features

* add optional ssl certificate support for https server ([22fce9e](https://github.com/darksworm/doormouse/commit/22fce9ed3f41432d9c8c94941b6fa17b264e86a8))
* add response_header_timeout to config to remove hard-coded 60 s value and allow long-running requests ([89f65c1](https://github.com/darksworm/doormouse/commit/89f65c1d5f1cdf8bdf2cd974e261fa3340c8a3b4))
* bombard host with multiple WOL packets until it wakes ([9f2e3ac](https://github.com/darksworm/doormouse/commit/9f2e3ac8b45c5f9ee5b2f5c58f3f9614345d184e))
* health check logging ([#16](https://github.com/darksworm/doormouse/issues/16)) ([3b82ff9](https://github.com/darksworm/doormouse/commit/3b82ff9a382953586aa2400fa175cf066c466ea2))
* shutdown after inactivity [#1](https://github.com/darksworm/doormouse/issues/1) ([#4](https://github.com/darksworm/doormouse/issues/4)) ([d36a7c9](https://github.com/darksworm/doormouse/commit/d36a7c99f7944dc54556694b4d748d8e2a8817c5))
* shutdown via HTTP request ([#11](https://github.com/darksworm/doormouse/issues/11)) ([ab31ee9](https://github.com/darksworm/doormouse/commit/ab31ee92e28fd7ae87e2389b914f7ea25e0e70fe))
* split targets into machines and routes, add TCP routes ([#20](https://github.com/darksworm/doormouse/issues/20)) ([5d59916](https://github.com/darksworm/doormouse/commit/5d599160b60f3741173a61f7d78710bbda8cc010))


### Bug Fixes

* ensure proper host ([0656102](https://github.com/darksworm/doormouse/commit/0656102d3ce7edc141ca1c2ba4b4518adcb93132))
* ensure target is always shut down ([43b6dc1](https://github.com/darksworm/doormouse/commit/43b6dc19299d6acd2c71db476e00edcff06042b2))
* for uploads ([1503b76](https://github.com/darksworm/doormouse/commit/1503b76347ce2c03f2f235aef4e1ea4e47dbefc2))
* hold IsWaking for the whole wake; add Clock seam, tests and CI ([#19](https://github.com/darksworm/doormouse/issues/19)) ([4c6cc41](https://github.com/darksworm/doormouse/commit/4c6cc4177a71cf790d442cd76038d7d052451eb2))
* reference correct targets [#3](https://github.com/darksworm/doormouse/issues/3) ([1350288](https://github.com/darksworm/doormouse/commit/1350288a426d56c7003582f027daf1d206102c9c))
* use fresh connections for health checks ([#17](https://github.com/darksworm/doormouse/issues/17)) ([9e164fc](https://github.com/darksworm/doormouse/commit/9e164fc2e9a20a968077f37101cbca48fc5a04ed))
