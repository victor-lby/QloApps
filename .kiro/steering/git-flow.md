# QloApps Git Flow Guidelines

## Overview

This document outlines the Git workflow and branching strategy for QloApps development, ensuring consistent code management, quality control, and deployment processes.

## Branching Strategy

### Main Branches

#### `main` (Production Branch)
- **Purpose**: Production-ready code
- **Protection**: Protected branch with required reviews
- **Deployment**: Automatically deployed to production
- **Merge Policy**: Only from `release/*` or `hotfix/*` branches
- **Naming**: `main`

#### `develop` (Development Branch)
- **Purpose**: Integration branch for features
- **Protection**: Protected branch with required reviews
- **Deployment**: Automatically deployed to staging
- **Merge Policy**: From `feature/*` branches via Pull Requests
- **Naming**: `develop`

### Supporting Branches

#### Feature Branches
- **Purpose**: New features and enhancements
- **Source**: Branch from `develop`
- **Merge Target**: `develop`
- **Naming Convention**: `feature/[ticket-id]-[short-description]`
- **Examples**:
  - `feature/HTL-123-booking-calendar`
  - `feature/HTL-456-room-management`
  - `feature/HTL-789-payment-integration`

#### Release Branches
- **Purpose**: Prepare new production releases
- **Source**: Branch from `develop`
- **Merge Target**: `main` and `develop`
- **Naming Convention**: `release/[version]`
- **Examples**:
  - `release/1.2.0`
  - `release/2.0.0-beta`

#### Hotfix Branches
- **Purpose**: Critical production fixes
- **Source**: Branch from `main`
- **Merge Target**: `main` and `develop`
- **Naming Convention**: `hotfix/[version]-[issue-description]`
- **Examples**:
  - `hotfix/1.1.1-booking-bug`
  - `hotfix/1.1.2-payment-error`

#### Module Development Branches
- **Purpose**: Specific module development
- **Source**: Branch from `develop`
- **Merge Target**: `develop`
- **Naming Convention**: `module/[module-name]-[feature]`
- **Examples**:
  - `module/hotelreservation-calendar`
  - `module/roommanagement-features`
  - `module/paymentgateway-stripe`

## Workflow Processes

### Feature Development Workflow

#### 1. Start New Feature
```bash
# Switch to develop branch
git checkout develop
git pull origin develop

# Create feature branch
git checkout -b feature/HTL-123-booking-calendar

# Push branch to remote
git push -u origin feature/HTL-123-booking-calendar
```

#### 2. Development Process
```bash
# Make changes and commit regularly
git add .
git commit -m "HTL-123: Add booking calendar component

- Implement calendar widget
- Add date selection functionality
- Update booking form integration"

# Push changes regularly
git push origin feature/HTL-123-booking-calendar
```

#### 3. Feature Completion
```bash
# Ensure feature branch is up to date
git checkout develop
git pull origin develop
git checkout feature/HTL-123-booking-calendar
git merge develop

# Resolve any conflicts and test
# Push final changes
git push origin feature/HTL-123-booking-calendar

# Create Pull Request to develop branch
```

### Release Workflow

#### 1. Prepare Release
```bash
# Create release branch from develop
git checkout develop
git pull origin develop
git checkout -b release/1.2.0
git push -u origin release/1.2.0
```

#### 2. Release Preparation
```bash
# Update version numbers
# Update CHANGELOG.md
# Run final tests
# Fix any release-specific issues

git add .
git commit -m "Prepare release 1.2.0

- Update version to 1.2.0
- Update changelog
- Fix release issues"

git push origin release/1.2.0
```

#### 3. Release Deployment
```bash
# Merge to main
git checkout main
git pull origin main
git merge --no-ff release/1.2.0
git tag -a v1.2.0 -m "Release version 1.2.0"
git push origin main --tags

# Merge back to develop
git checkout develop
git merge --no-ff release/1.2.0
git push origin develop

# Delete release branch
git branch -d release/1.2.0
git push origin --delete release/1.2.0
```

### Hotfix Workflow

#### 1. Create Hotfix
```bash
# Create hotfix branch from main
git checkout main
git pull origin main
git checkout -b hotfix/1.1.1-booking-bug
git push -u origin hotfix/1.1.1-booking-bug
```

#### 2. Fix and Test
```bash
# Make necessary fixes
git add .
git commit -m "Fix critical booking bug

- Resolve room availability calculation
- Fix date validation issue
- Add error handling"

git push origin hotfix/1.1.1-booking-bug
```

#### 3. Deploy Hotfix
```bash
# Merge to main
git checkout main
git merge --no-ff hotfix/1.1.1-booking-bug
git tag -a v1.1.1 -m "Hotfix version 1.1.1"
git push origin main --tags

# Merge to develop
git checkout develop
git merge --no-ff hotfix/1.1.1-booking-bug
git push origin develop

# Delete hotfix branch
git branch -d hotfix/1.1.1-booking-bug
git push origin --delete hotfix/1.1.1-booking-bug
```

## Commit Message Standards

### Commit Message Format
```
[TICKET-ID]: [Type] [Short description]

[Optional detailed description]

[Optional breaking changes note]
```

### Commit Types
- **feat**: New feature
- **fix**: Bug fix
- **docs**: Documentation changes
- **style**: Code style changes (formatting, etc.)
- **refactor**: Code refactoring
- **test**: Adding or updating tests
- **chore**: Maintenance tasks
- **perf**: Performance improvements
- **security**: Security improvements

### Examples
```bash
# Feature commit
git commit -m "HTL-123: feat: Add room booking calendar

Implement interactive calendar for room booking
- Add date picker component
- Integrate with availability API
- Update booking form validation"

# Bug fix commit
git commit -m "HTL-456: fix: Resolve payment processing error

Fix issue where payment fails on room booking
- Update payment gateway integration
- Add proper error handling
- Improve user feedback"

# Documentation commit
git commit -m "HTL-789: docs: Update API documentation

Add documentation for new booking endpoints
- Document booking creation API
- Add example requests/responses
- Update authentication section"
```

## Module Development Guidelines

### Module-Specific Branches
```bash
# Create module development branch
git checkout develop
git checkout -b module/hotelreservation-v2

# Module feature branches
git checkout -b module/hotelreservation-calendar
git checkout -b module/hotelreservation-payments
git checkout -b module/hotelreservation-notifications
```

### Module Release Process
```bash
# Prepare module release
git checkout module/hotelreservation-v2
git merge module/hotelreservation-calendar
git merge module/hotelreservation-payments
git merge module/hotelreservation-notifications

# Test module integration
# Update module version
# Create module package

# Merge to develop
git checkout develop
git merge --no-ff module/hotelreservation-v2
```

## Code Review Process

### Pull Request Requirements
1. **Branch Protection**: All protected branches require PR reviews
2. **Required Reviewers**: Minimum 2 reviewers for main branches
3. **Status Checks**: All CI/CD checks must pass
4. **Conflict Resolution**: No merge conflicts allowed
5. **Documentation**: Update relevant documentation

### Review Checklist
- [ ] Code follows QloApps coding standards
- [ ] All tests pass
- [ ] Security considerations addressed
- [ ] Performance impact assessed
- [ ] Documentation updated
- [ ] Database migrations included (if needed)
- [ ] Module compatibility verified
- [ ] API changes documented

### PR Template
```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update
- [ ] Module update

## Testing
- [ ] Unit tests added/updated
- [ ] Integration tests pass
- [ ] Manual testing completed
- [ ] Performance testing done

## Checklist
- [ ] Code follows style guidelines
- [ ] Self-review completed
- [ ] Documentation updated
- [ ] No merge conflicts
- [ ] All CI checks pass

## Related Issues
Closes #123
Related to #456
```

## Environment Management

### Branch-Environment Mapping
```
main branch        → Production Environment
develop branch     → Staging Environment
feature/* branches → Development Environment
release/* branches → Pre-production Environment
hotfix/* branches  → Hotfix Testing Environment
```

### Deployment Pipeline
```yaml
# .github/workflows/deploy.yml
name: Deploy Pipeline

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main, develop]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Setup PHP
        uses: shivammathur/setup-php@v2
        with:
          php-version: '8.1'
      - name: Install dependencies
        run: composer install
      - name: Run tests
        run: ./vendor/bin/phpunit
      - name: Run security checks
        run: ./vendor/bin/security-checker security:check

  deploy-staging:
    if: github.ref == 'refs/heads/develop'
    needs: test
    runs-on: ubuntu-latest
    steps:
      - name: Deploy to Staging
        run: |
          # Deployment script for staging

  deploy-production:
    if: github.ref == 'refs/heads/main'
    needs: test
    runs-on: ubuntu-latest
    steps:
      - name: Deploy to Production
        run: |
          # Deployment script for production
```

## Version Management

### Semantic Versioning
- **MAJOR.MINOR.PATCH** (e.g., 2.1.3)
- **MAJOR**: Breaking changes
- **MINOR**: New features (backward compatible)
- **PATCH**: Bug fixes (backward compatible)

### Version Tagging
```bash
# Create version tag
git tag -a v1.2.0 -m "Release version 1.2.0

New Features:
- Advanced booking calendar
- Room management improvements
- Payment gateway integration

Bug Fixes:
- Fixed availability calculation
- Resolved email notification issues"

# Push tags
git push origin --tags
```

### Changelog Management
```markdown
# CHANGELOG.md

## [1.2.0] - 2024-01-15

### Added
- New booking calendar interface
- Room management dashboard
- Stripe payment integration
- Guest notification system

### Changed
- Improved booking form validation
- Updated admin interface design
- Enhanced API response format

### Fixed
- Room availability calculation bug
- Email template rendering issue
- Payment processing timeout

### Security
- Updated authentication system
- Fixed SQL injection vulnerability
```

## Best Practices

### Branch Management
1. **Keep branches focused**: One feature per branch
2. **Regular updates**: Sync with develop frequently
3. **Clean history**: Use meaningful commit messages
4. **Delete merged branches**: Clean up after merging
5. **Protect important branches**: Use branch protection rules

### Collaboration Guidelines
1. **Communication**: Discuss major changes before implementation
2. **Code reviews**: Always review code before merging
3. **Testing**: Ensure all tests pass before merging
4. **Documentation**: Keep documentation up to date
5. **Issue tracking**: Link commits to issue tickets

### Security Considerations
1. **Sensitive data**: Never commit secrets or credentials
2. **Code scanning**: Use automated security scanning
3. **Dependency updates**: Keep dependencies updated
4. **Access control**: Limit repository access appropriately
5. **Audit trail**: Maintain clear commit history

This Git Flow strategy ensures organized development, quality control, and reliable deployments for QloApps hotel management system.