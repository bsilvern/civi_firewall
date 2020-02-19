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

  if ($params['delete_old'] !== 0 && !empty($params['delete_old'])) {
    // Delete all locally recorded paymentIntents that are older than 3 months
    $results = \Civi\Api4\FirewallIpaddress::delete()
      ->addWhere('access_date', '<', ['delete_old'])
      ->execute();
  }

  return civicrm_api3_create_success($results, $params);
}

/**
 * @param array $params
 *
 */
function _civicrm_api3_job_firewall_cleanup_spec(&$params) {
  $params['delete_old']['api.default'] = '-1 month';
  $params['delete_old']['title'] = 'Delete old records after (default: -1 month)';
  $params['delete_old']['description'] = 'Delete old records from database. Specify 0 to disable. Default is "-1 month"';
}
