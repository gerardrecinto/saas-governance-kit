output "protected_repositories" {
  description = "Repositories with default-branch protection managed here"
  value       = keys(github_branch_protection.default)
}
