## Release Notes

### 1.1

* Add Firewall.Getcsrf and Firewall.Getcsrfisvalid APIv3 functions.
* Change the way we generate/validate CSRF tokens so they do not rely on session (or any) storage:

  *Previously this was stored in the user session but this causes problems if you request more than one token in the same session (eg. by opening multiple payment pages in different browser tabs).*

* Fix parameters for API3 `Job.firewall_cleanup`.
* Don't log changes to `civicrm_firewall_ipaddress` table.

### 1.0.3

* Regenerate DAO (Data Access Object) files to support changes in CiviCRM 5.27+.

### 1.0.2

* Don't specify ROW_FORMAT=DYNAMIC when installing (leave it to CiviCRM/database to decide).

### 1.0.1

* Fix [#5](https://lab.civicrm.org/extensions/firewall/-/issues/5) Api4 related error with Firewall: Cleanup job

### 0.2 / 1.0

* Specify database Engine=InnoDB and Row format = DYNAMIC to resolve installation issues on some database servers.

### 0.1

* Initial Release
