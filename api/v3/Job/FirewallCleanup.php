<?php
/**
 * This job performs various housekeeping actions related to the Firewall
 *
 * @param array $params
 *
 * @return array
 *   API result array.
 * @throws CiviCRM_API3_Exception
 */
function civicrm_api3_job_firewall_cleanup($params) {
  $results = [];

  if (!empty($params['delete_old_ipaddress'])) {
    // Delete all locally recorded paymentIntents that are older than 3 months
    $results = \Civi\Api4\FirewallIpaddress::delete()
      ->addWhere('access_date', '<', $params['delete_old_ipaddress'])
      ->execute();
  }
  if (!empty($params['delete_old_csrftoken'])) {
    // Delete all locally recorded paymentIntents that are older than 3 months
    $results = \Civi\Api4\FirewallCsrfToken::delete()
      ->addWhere('created_date', '<', $params['delete_old_csrftoken'])
      ->execute();
  }

  return civicrm_api3_create_success((array) $results, $params);
}

/**
 * @param array $params
 *
 */
function _civicrm_api3_job_firewall_cleanup_spec(&$params) {
  $params['delete_old_ipaddress']['api.default'] = '-1 month';
  $params['delete_old_ipaddress']['api.aliases'] = ['delete_old'];
  $params['delete_old_ipaddress']['title'] = 'Delete old ip address records after (default: -1 month)';
  $params['delete_old_ipaddress']['description'] = 'Delete old ip address from database. Specify 0 to disable. Default is "-1 month"';
  $params['delete_old_csrftoken']['api.default'] = '-1 week';
  $params['delete_old_csrftoken']['api.aliases'] = ['delete_old_csrftoken'];
  $params['delete_old_csrftoken']['title'] = 'Delete old CSRF token records after (default: -1 week)';
  $params['delete_old_csrftoken']['description'] = 'Delete old CSRF tokens from database. Specify 0 to disable. Default is "-1 week"';
}
