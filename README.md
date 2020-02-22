# firewall

This implements a simple firewall for CiviCRM that blocks by IP address in various scenarios.

This is currently a very simple automatic solution with no config and no configuration. It is expected that will change in the future.

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

## Installation

See: https://docs.civicrm.org/sysadmin/en/latest/customize/extensions/#installing-a-new-extension

## Usage

## Administration

* Job.Firewall_cleanup: There is a scheduled job which cleans old entries from the `civicrm_firewall_ipaddress` table after 1 month.

## Future Development / Ideas

Thanks to @artfulrobot for testing and writing down some ideas for future development.

* Some forensic logging of bad things happening would be good. Who made the request, why was it bad, what was the content of the request, what was the user agent and the http method, were they logged in (!) - and as which user, is there any other relevant context? This way sites can use that data to be clevererer with setting limits/identifying traits of spammers.
* All rates/limits should be configurable (limit and period per event; how long logs are kept for).
* csrf tokens could include time limits and getter / checker could also take a param for the purpose - so one token doesn't work across different forms/purposes. Is there an advantage to tying in the IP to the token, too? I know you said this could come later.
* I like the idea that we could use it for more stuff, like thwarting other form submission spam.
* Also, should we log when we've denied someone something? I know there's the server logs with 403s. Just thinking that when I've been in this sort of situation, you can never get enough information. e.g. if it's baddies: need to study their behaviour; if it's goodies getting frustrated, good to understand what happened there, too, as it may help solve a supporter relations issue.

  *Currently the records are kept in the database table for one month. So you can work out when an IP was blocked - but it does require a bit of calculation.*
