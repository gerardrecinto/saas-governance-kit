provider "github" {
  owner = var.github_owner
  # Token comes from the GITHUB_TOKEN environment variable.
}

provider "slack" {
  # Token comes from the SLACK_TOKEN environment variable.
}

resource "github_repository" "managed" {
  for_each = var.repositories

  name                   = each.key
  description            = each.value.description
  visibility             = each.value.visibility
  has_issues             = true
  delete_branch_on_merge = true
}

resource "github_repository_vulnerability_alerts" "managed" {
  for_each = var.repositories

  repository = github_repository.managed[each.key].name
  enabled    = true
}

resource "github_branch_protection" "default" {
  for_each = var.repositories

  repository_id  = github_repository.managed[each.key].node_id
  pattern        = each.value.default_branch
  enforce_admins = true

  allows_force_pushes = false
  allows_deletions    = false

  required_status_checks {
    strict   = true
    contexts = var.required_status_checks
  }

  required_pull_request_reviews {
    required_approving_review_count = var.required_approving_reviews
    dismiss_stale_reviews           = true
  }
}

resource "github_team" "access" {
  for_each = var.access_groups

  name    = each.key
  privacy = "closed"
}

resource "github_team_membership" "access" {
  for_each = {
    for pair in flatten([
      for team, logins in var.access_groups : [
        for login in logins : { key = "${team}/${login}", team = team, login = login }
      ]
    ]) : pair.key => pair
  }

  team_id  = github_team.access[each.value.team].id
  username = each.value.login
  role     = "member"
}

resource "slack_conversation" "approvals" {
  name              = var.approver_channel_name
  topic             = "Access request approvals"
  permanent_members = []
  is_private        = true
}

resource "slack_usergroup" "managed" {
  for_each = var.slack_usergroups

  name        = each.value.name
  handle      = each.key
  description = each.value.description
}
