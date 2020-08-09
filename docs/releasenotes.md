## Release Notes

### 1.1

* Use a table to store generated CSRF tokens (`civicrm_firewall_csrf_token`).

  *Previously this was stored in the user session but this causes problems if you request more than one token in the same session (eg. by opening multiple payment pages in different browser tabs).*

* Fix issue with cleanup job always deleting all records.
* Add configurable CSRF token timeout via hidden setting (`firewall_csrf_timeout`) - default 24 hours.

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
