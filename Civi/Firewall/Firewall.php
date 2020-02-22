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
namespace Civi\Firewall;

class Firewall {

  /**
   * The main entry point that is called from hook_civicrm_config (the earliest point we can intercept via extension).
   */
  public function run() {
    if ($this->shouldThisRequestBeBlocked()) {
      // Block them
      http_response_code(403); // Forbidden
      exit();
    }
  }

  /**
   * Perform the actual checks.
   *
   * @return bool
   */
  public function shouldThisRequestBeBlocked() {
    // @todo make these settings configurable.
    // If there are more than COUNT triggers for this event within time interval then block
    $interval = 'INTERVAL 2 HOUR';
    $queryParams = [
      // The client IP address
      1 => [\CRM_Utils_System::ipAddress(), 'String'],
    ];
    $blockFraudAfter = 5;
    $blockInvalidCSRFAfter = 5;

    $sql = "
SELECT COUNT(*) as eventCount,event_type FROM `civicrm_firewall_ipaddress`
WHERE access_date >= DATE_SUB(NOW(), {$interval})
AND ip_address = %1
GROUP BY event_type
    ";

    $block = FALSE;
    $dao = \CRM_Core_DAO::executeQuery($sql, $queryParams);
    while ($dao->fetch()) {
      switch ($dao->event_type) {
        case 'FraudEvent':
          if ($dao->eventCount >= $blockFraudAfter) {
            $block = TRUE;
            break 2;
          }
          break;

        case 'InvalidCSRFEvent':
          if ($dao->eventCount >= $blockInvalidCSRFAfter) {
            $block = TRUE;
            break 2;
          }
          break;
      }
    }
    return $block;
  }

  /**
   * Generate and store a CSRF token. Clients will need to retreive and pass this into AJAX/API requests.
   *
   * @return string
   */
  public static function getCSRFToken(): string {
    $token = base64_encode(openssl_random_pseudo_bytes(32));
    \CRM_Core_Session::singleton()->set('firewall_csrftoken', $token);
    return $token;
  }

  /**
   * Check if the passed in CSRF token is valid and trigger InvalidCSRFEvent if invalid.
   *
   * @param string $token
   *
   * @return bool
   */
  public static function isCSRFTokenValid(string $token): bool {
    if (!empty($token) && (\CRM_Core_Session::singleton()->get('firewall_csrftoken') === $token)) {
      return TRUE;
    }
    \Civi\Firewall\Event\InvalidCSRFEvent::trigger(\CRM_Utils_System::ipAddress(), NULL);
    return FALSE;
  }

}
