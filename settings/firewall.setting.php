<?php
/*
 +--------------------------------------------------------------------+
 | Copyright CiviCRM LLC. All rights reserved.                        |
 |                                                                    |
 | This work is published under the GNU AGPLv3 license with some      |
 | permitted exceptions and without any warranty. For full license    |
 | and copyright information, see https://civicrm.org/licensing       |
 +--------------------------------------------------------------------+
 */

use CRM_Firewall_ExtensionUtil as E;

return [
  'firewall_csrf_timeout' => [
    'name' => 'firewall_csrf_timeout',
    'type' => 'Integer',
    'html_type' => 'Text',
    'default' => 43200,
    'is_domain' => 1,
    'is_contact' => 0,
    'title' => E::ts('Firewall CSRF timeout (seconds)'),
    'description' => E::ts('Time after which generated CSRF token expires (default 12 hours: 43200 seconds)'),
    'html_attributes' => [],
  ],
];
