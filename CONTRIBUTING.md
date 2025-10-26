# Contributing to nest-auth-kit

First off, thank you for considering contributing to this project! 🎉

## Code of Conduct

This project and everyone participating in it is governed by our Code of Conduct. By participating, you are expected to uphold this code.

## How Can I Contribute?

### Reporting Bugs

Before creating bug reports, please check the existing issues to avoid duplicates. When you create a bug report, include as many details as possible:

- **Use a clear and descriptive title**
- **Describe the exact steps to reproduce the problem**
- **Provide specific examples**
- **Describe the behavior you observed and what you expected**
- **Include your environment details** (Node version, NestJS version, etc.)

### Suggesting Enhancements

Enhancement suggestions are tracked as GitHub issues. When creating an enhancement suggestion:

- **Use a clear and descriptive title**
- **Provide a detailed description of the suggested enhancement**
- **Explain why this enhancement would be useful**
- **List any alternatives you've considered**

### Pull Requests

1. Fork the repo and create your branch from `main`
2. If you've added code, add tests
3. Ensure the test suite passes
4. Make sure your code follows the existing style
5. Write a clear commit message
6. Open a Pull Request

## Development Setup

```bash
# Clone your fork
git clone https://github.com/your-username/nestjs-auth.git
cd nestjs-auth

# Install dependencies
npm install

# Build the project
npm run build

# Run tests
npm test

# Run linter
npm run lint
```

## Project Structure

```md
src/
├── core/            # Interfaces and types
├── implementations/ # Base and default services
├── strategies/      # Passport strategies
├── guards/          # Authentication guards
├── decorators/      # Custom decorators
├── session/         # Session stores
└── modules/         # NestJS modules
```

## Coding Guidelines

- Use TypeScript
- Follow the existing code style
- Write meaningful commit messages
- Add JSDoc comments for public APIs
- Add tests for new features
- Update documentation

## Commit Message Guidelines

We follow conventional commits:

- `feat:` New feature
- `fix:` Bug fix
- `docs:` Documentation changes
- `style:` Code style changes (formatting, etc.)
- `refactor:` Code refactoring
- `test:` Adding or updating tests
- `chore:` Maintenance tasks

Example: `feat: add Apple OAuth strategy`

## Questions?

Feel free to open an issue with your question or reach out to the maintainers.

Thank you! 🙌

```md

### **3. LICENSE**
```

MIT License

Copyright (c) 2024 Your Organization

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

```md

### **4. .npmignore**
```

# Source files

src/
*.ts
!*.d.ts

# Tests

test/
tests/
*.spec.ts
*.test.ts

# Development files

.git/
.github/
.vscode/
.idea/
*.log
node_modules/

# Documentation

docs/
examples/
*.md
!README.md

# Config files

.eslintrc.*
.prettierrc.*
tsconfig.json
tsconfig.*.json
jest.config.*
