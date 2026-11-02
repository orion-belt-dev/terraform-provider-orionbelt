# compliance-violation

- Deliberately breaks PCI DSS 4.0: shared `admin` account, `root` grant, no expiry.
- Shows the provider rejecting it at plan time with the rule id and control citations. No gateway is contacted.

```sh
terraform init   # or use dev_overrides
terraform plan
```

Expected output:

```text
Error: Compliance violation: no-shared-accounts

  with orionbelt_user.shared,
  on main.tf line 19, in resource "orionbelt_user" "shared":
  19:   username = "admin"

username "admin" looks like a shared account; accounts must belong to one
person (PCI DSS 4.0 8.2.1, PCI DSS 4.0 8.2.2)

Error: Compliance violation: grant-expiry

  with orionbelt_permission.root_forever,
  on main.tf line 23, in resource "orionbelt_permission" "root_forever":
  23: resource "orionbelt_permission" "root_forever" {

access grants must expire; set expires_at (PCI DSS 4.0 7.2.4)

Error: Compliance violation: denied-remote-user

  with orionbelt_permission.root_forever,
  on main.tf line 28, in resource "orionbelt_permission" "root_forever":
  28:   remote_users = ["root"]

remote user "root" is not allowed; grant a named, least-privileged account
(PCI DSS 4.0 7.2.2, PCI DSS 4.0 8.6.1)
```
