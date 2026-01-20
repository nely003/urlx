# Contributing to urlX

First off, thank you for considering contributing to urlX! It's people like you that make urlX such a great tool.

## Code of Conduct

This project and everyone participating in it is governed by our Code of Conduct. By participating, you are expected to uphold this code.

## How Can I Contribute?

### Reporting Bugs

Before creating bug reports, please check the existing issues as you might find out that you don't need to create one. When you are creating a bug report, please include as many details as possible:

* **Use a clear and descriptive title**
* **Describe the exact steps to reproduce the problem**
* **Provide specific examples to demonstrate the steps**
* **Describe the behavior you observed and what behavior you expected**
* **Include screenshots if possible**
* **Include your environment details** (OS, Go version, etc.)

### Suggesting Enhancements

Enhancement suggestions are tracked as GitHub issues. When creating an enhancement suggestion, please include:

* **Use a clear and descriptive title**
* **Provide a step-by-step description of the suggested enhancement**
* **Provide specific examples to demonstrate the steps**
* **Describe the current behavior and expected behavior**
* **Explain why this enhancement would be useful**

### Adding New Data Sources

We're always looking to add more URL discovery sources! To add a new source:

1. **Implement the URLSource interface:**

```go
type YourNewSource struct {
    client *http.Client
    apiKey string // if needed
}

func (y *YourNewSource) Name() string {
    return "Your Source Name"
}

func (y *YourNewSource) Fetch(domain string) ([]string, error) {
    // Your implementation here
    // Return a slice of URLs found
}
```

2. **Add it to the collector in `main.go`:**

```go
func NewURLCollector(verbose bool, config map[string]string) *URLCollector {
    // ... existing sources ...
    
    if config["yoursource"] != "" {
        sources = append(sources, &YourNewSource{
            client: client,
            apiKey: config["yoursource"],
        })
    }
}
```

3. **Add command-line flag:**

```go
yourSourceKey = flag.String("yoursource-key", "", "Your Source API key")
```

4. **Update README.md** with the new source information

5. **Test thoroughly** with various domains

### Pull Requests

* Fill in the required template
* Do not include issue numbers in the PR title
* Follow the Go coding style guide
* Include tests when adding new features
* Update documentation as needed
* End all files with a newline

## Development Process

1. **Fork the repo** and create your branch from `main`
2. **Make your changes** following our style guide
3. **Test your changes** thoroughly
4. **Update documentation** if needed
5. **Commit your changes** with clear commit messages
6. **Push to your fork** and submit a pull request

## Style Guide

### Go Code Style

* Follow standard Go formatting (`gofmt`)
* Use meaningful variable names
* Add comments for complex logic
* Keep functions focused and small
* Handle errors appropriately
* Use context for cancellation when appropriate

### Commit Messages

* Use the present tense ("Add feature" not "Added feature")
* Use the imperative mood ("Move cursor to..." not "Moves cursor to...")
* Limit the first line to 72 characters or less
* Reference issues and pull requests liberally after the first line

Example:
```
Add support for Shodan API integration

- Implement Shodan source struct
- Add API key configuration
- Update documentation
- Add integration tests

Fixes #123
```

## Testing

Before submitting a pull request:

1. **Test with multiple domains:**
```bash
./urlx -domain example.com -v
./urlx -d test-domains.txt -v
```

2. **Test with various API keys:**
```bash
./urlx -domain example.com \
  -urlscan-key TEST_KEY \
  -otx-key TEST_KEY \
  -v
```

3. **Test error handling:**
   - Invalid domains
   - Network errors
   - Invalid API keys
   - Empty responses

4. **Check for race conditions:**
```bash
go test -race ./...
```

## Project Structure

```
urlx/
├── main.go              # Main application
├── README.md            # Project documentation
├── LICENSE              # MIT License
├── CONTRIBUTING.md      # This file
├── go.mod               # Go module definition
├── go.sum               # Go dependencies
├── .github/
│   ├── workflows/       # CI/CD workflows
│   └── ISSUE_TEMPLATE/  # Issue templates
├── docs/                # Additional documentation
├── examples/            # Usage examples
└── tests/               # Test files
```

## Setting Up Development Environment

1. **Install Go 1.19 or later:**
```bash
# Check version
go version
```

2. **Clone your fork:**
```bash
git clone https://github.com/yourusername/urlx.git
cd urlx
```

3. **Install dependencies:**
```bash
go mod download
```

4. **Build the project:**
```bash
go build -o urlx main.go
```

5. **Run tests:**
```bash
go test -v ./...
```

## Adding Documentation

When adding new features, please update:

1. **README.md** - Add usage examples and flag descriptions
2. **Code comments** - Document exported functions and types
3. **Examples** - Add practical examples in `examples/` directory

## Performance Considerations

When contributing code:

* Avoid unnecessary allocations
* Use buffered channels appropriately
* Consider memory usage with large datasets
* Use goroutines wisely (don't create unlimited goroutines)
* Profile performance-critical code

## Security Considerations

* Never commit API keys or secrets
* Validate all user input
* Handle rate limiting appropriately
* Respect robots.txt when applicable
* Follow responsible disclosure practices

## Questions?

Feel free to open an issue with the `question` label or reach out to the maintainers.

## Recognition

Contributors will be recognized in:
* README.md acknowledgments
* Release notes
* GitHub contributors page

Thank you for contributing to urlX! 🎉
