<?php
// This file declares a new entity type. For more details, see "hook_civicrm_entityTypes" at:
// https://docs.civicrm.org/dev/en/latest/hooks/hook_civicrm_entityTypes
return [
  [
    'name' => 'FirewallCsrfToken',
    'class' => 'CRM_Firewall_DAO_FirewallCsrfToken',
    'table' => 'civicrm_firewall_csrf_token',
  ],
];
