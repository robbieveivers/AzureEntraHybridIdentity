locals {
  flattened_rules = flatten([
    for subnet_key, subnet_value in var.subnets : [
      for rule in (subnet_value.nsg != null ? subnet_value.nsg.rules : []) : {
        subnet_key = subnet_key
        rule       = rule
      }
    ]
  ])
}