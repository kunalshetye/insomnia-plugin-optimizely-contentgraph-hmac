# Optimizely ContentGraph HMAC Signing for Insomnia

Adds HMAC signature to optimizely content graph API calls.

## Prerequisite
Requires the following environment variables to be present
- AppKey
- Secret
- GatewayAddress

**Note: The plugin only adds the Authentication header if the ?auth={SingleKey} parameter is missing from the url. This allows you to fetch published content with ?auth paramter and draft content with hmac authentication**

## Install

1. In Insomnia, go to _Application_ and select _Preferences_
2. Click on _Plugins_
3. Paste `insomnia-plugin-optimizely-contentgraph-hmac` into the package name field
4. Click on _Install Plugin_

## License

[MIT License](./LICENSE)
