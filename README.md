# PR Commenter Plugin [![Build status](https://badge.buildkite.com/70e1d545dabb9e07d0c52537f5ae31e4d1f225e130e33ebcae.svg?branch=main)](https://buildkite.com/buildkite/plugins-pr-commenter)
A Buildkite plugin written in Go that enables commenting on pull requests that builds are triggered from.

The plugin uses the `/issues` endpoint as that doesn't require a commit SHA or file name in order to post the comment; this comment will post to the `conversation` tab and won't be associated with any file changes.

The plugin has been tested and built using **go 1.20.3**, so it is not guaranteed to work on versions **<1.20.3**.

The plugin binary will get built in the step and output as a `pre-exit` hook. This ensures that it runs as the last command on the step and is able to get the *exit code* of the step that it runs on (necessary for the default message).

The use of this plugin requires that clusters are being used and that the secret is available on that cluster, else the plugin will error.

## 👩‍💻 Usage

Add the following to your `pipeline.yml`:

```yaml
    steps:
        command: echo "cool plugin!"
        plugins:
            - pr-commenter#v0.0.1:
                message: "LGTM!"
                secret-name: GITHUB_TOKEN
```

## 📒 Options

### `secret-name` (optional, string)
The environment variable that contains the value of the GitHub API token. If not set, the plugin will try to get the URL from the default configuration.

Default: `GITHUB_TOKEN`

### `message` (optional, string)
The message which should be posted to the PR. This can be a dynamic value, such as `$BUILDKITE_COMMAND`

Default: `[https://buildkite.com/mock-org/cool-pipeline/builds/420#step-id](https://buildkite.com/mock-org/cool-pipeline/builds/420#step-id) exited with code 0`

## Compatibility

| Elastic Stack | Agent Stack K8s | Hosted (Mac) | Hosted (Linux) | Notes |
| :-----------: | :-------------: | :----: | :----: |:---- |
| ✅ | ⚠️ | ✅ | ✅ | K8s: The `go` binary will need to be available on the agents |

- ✅ Fully supported (all combinations of attributes have been tested to pass)
- ⚠️ Partially supported (some combinations cause errors/issues)

## 🛠️ Development
### Running the tests
The tests are written using Go's built-in testing package.

Tests can be run using:

```shell
go test -v ./...
```


## 💪 Contributing

We welcome all contributions to improve this plugin! To contribute, please follow these guidelines:

- Fork the repository
- Make your changes and ensure that the tests pass.
- Write clear and concise commit messages.
- Submit a pull request.

By contributing, you agree to license your contributions under the LICENSE file of this repository.

## License
MIT (see [LICENSE](LICENSE.MD))
