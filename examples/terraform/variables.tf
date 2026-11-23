variable "github_owner" {
  description = "GitHub organization that owns the repositories"
  type        = string
}

variable "repositories" {
  description = "Repositories to manage and their default branch"
  type = map(object({
    description    = string
    default_branch = optional(string, "main")
    visibility     = optional(string, "private")
  }))
}

variable "required_approving_reviews" {
  description = "Approvals required before merging to the default branch"
  type        = number
  default     = 1
}

variable "required_status_checks" {
  description = "Status check contexts that must pass before merge"
  type        = list(string)
  default     = ["ci"]
}

variable "access_groups" {
  description = "Teams that back requestable access groups, mapped to member logins"
  type        = map(list(string))
  default     = {}
}

variable "approver_channel_name" {
  description = "Slack channel that receives access-request approvals"
  type        = string
  default     = "access-approvals"
}

variable "slack_usergroups" {
  description = "Slack user groups to manage, keyed by handle"
  type = map(object({
    name        = string
    description = string
  }))
  default = {}
}
