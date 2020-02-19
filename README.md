# firewall

This implements a simple firewall for CiviCRM that blocks by IP address in various scenarios.

The extension is licensed under [AGPL-3.0](LICENSE.txt).

### Scenarios

#### Fraud Events

You can trigger a Fraud Event by calling:
```php
\Civi\Firewall\Event\FraudEvent::trigger([ip address], "my helpful description");
```

If 5 or more fraud events from the same IP address are triggered within 2 hours the IP address will be blocked for 2 hours.
Once the number of fraud events in a 2 hour period drop below 5 the IP address will be automatically unblocked again.

#### Invalid CSRF Events

If you implement APIs or AJAX endpoints which require anonymous access (eg. a javascript based payment processor
such as [Stripe](https://lab.civicrm.org/extensions/stripe)) then you will probably need to protect them with a CSRF token.

First get a token and pass it to your form/endpoint:
```php
$myVars = [
  'token' => class_exists('\Civi\Firewall\Firewall') ? \Civi\Firewall\Firewall::getCSRFToken() : NULL,
];
```

Then in your API/AJAX endpoint check if the token is valid:
```php
if (class_exists('\Civi\Firewall\Firewall')) {
  if (!\Civi\Firewall\Firewall::isCSRFTokenValid(CRM_Utils_Request::retrieveValue('token', 'String'))) {
    self::returnInvalid();
  }
}
```

!!! Note: By checking if the class exists the firewall extension can be an optional dependency.


## Requirements

* PHP v7.1+
* CiviCRM 5.19+

## Requirements

* PHP v7.1+
* CiviCRM 5.19+

## Installation

See: https://docs.civicrm.org/sysadmin/en/latest/customize/extensions/#installing-a-new-extension

## Usage

## Administration

* Job.Firewall_cleanup: There is a scheduled job which cleans old entries from the `civicrm_firewall_ipaddress` table after 1 month.
