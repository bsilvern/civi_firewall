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
    'html_type' => 'text',
    'default' => 43200,
    'is_domain' => 1,
    'is_contact' => 0,
    'title' => E::ts('Firewall CSRF timeout (seconds)'),
    'description' => E::ts('Time after which generated CSRF token expires (default 12 hours: 43200 seconds)'),
    'html_attributes' => [],
    'settings_pages' => [
      'firewall' => [
        'weight' => 10,
      ]
    ],
  ],
  'firewall_reverse_proxy' => [
    'name' => 'firewall_reverse_proxy',
    'type' => 'Boolean',
    'html_type' => 'checkbox',
    'default' => 1,
    'is_domain' => 1,
    'is_contact' => 0,
    'title' => E::ts('Is server behind reverse proxy?'),
    'description' => E::ts('If yes, try to retrieve the IP address of the actual client instead of using REMOTE_ADDR header'),
    'html_attributes' => [],
    'settings_pages' => [
      'firewall' => [
        'weight' => 20,
      ]
    ],
  ],
  'firewall_reverse_proxy_header' => [
    'name' => 'firewall_reverse_proxy_header',
    'type' => 'String',
    'html_type' => 'text',
    'default' => 'HTTP_X_FORWARDED_FOR',
    'is_domain' => 1,
    'is_contact' => 0,
    'title' => E::ts('Firewall Reverse Proxy Header'),
    'description' => E::ts('Reverse Proxy Header (default HTTP_X_FORWARDED_FOR)'),
    'html_attributes' => [
      'size' => 40,
    ],
    'settings_pages' => [
      'firewall' => [
        'weight' => 30,
      ]
    ],
  ],
  'firewall_reverse_proxy_addresses' => [
    'name' => 'firewall_reverse_proxy_addresses',
    'type' => 'String',
    'html_type' => 'text',
    'default' => '',
    'is_domain' => 1,
    'is_contact' => 0,
    'title' => E::ts('List of reverse proxy IP addresses'),
    'description' => E::ts('List of reverse proxy IP addresses that may be seen by your server. Used to help identify client IP address'),
    'html_attributes' => [
      'size' => 80,
    ],
    'settings_pages' => [
      'firewall' => [
        'weight' => 40,
      ]
    ],
  ],
  'firewall_whitelist_addresses' => [
    'name' => 'firewall_whitelist_addresses',
    'type' => 'String',
    'html_type' => 'text',
    'default' => '127.0.0.1,::1',
    'is_domain' => 1,
    'is_contact' => 0,
    'title' => E::ts('List of IP addresses to whitelist'),
    'description' => E::ts('List of IP addresses that will never be blocked'),
    'html_attributes' => [
      'size' => 80,
    ],
    'settings_pages' => [
      'firewall' => [
        'weight' => 50,
      ]
    ],
  ],

];
