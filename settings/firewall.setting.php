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
    'type' => 'String',
    'html_type' => 'Text',
    'default' => '-24 hour',
    'is_domain' => 1,
    'is_contact' => 0,
    'title' => E::ts('Firewall CSRF timeout'),
    'description' => E::ts('Time after which generated CSRF token expires (default "-24 hour")'),
    'html_attributes' => [],
  ],
];
