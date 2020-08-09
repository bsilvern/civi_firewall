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

use Civi\Api4\FirewallCsrfToken;

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
    // @todo: If we make these settings configurable we also need to actually *load* the settings earlier
    //   Settings are not loaded when we are first called from firewall_civicrm_config
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
   * Generate and store a CSRF token. Clients will need to retrieve and pass this into AJAX/API requests.
   *
   * @return string
   */
  public static function getCSRFToken(): string {
    $token = base64_encode(openssl_random_pseudo_bytes(32));
    $source = [
      'ip_address' => \CRM_Utils_System::ipAddress(),
      'contact_id' => \CRM_Core_Session::getLoggedInContactID()
    ];
    \Civi\Api4\FirewallCsrfToken::create(FALSE)
      ->setValues(['token' => $token, 'source' => json_encode($source)])
      ->execute();
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
    if (!empty($token)) {
      $savedToken = \Civi\Api4\FirewallCsrfToken::get(FALSE)
        ->addWhere('token', '=', $token)
        ->addWhere('created_date', '>', \Civi::settings()->get('firewall_csrf_timeout'))
        ->execute()
        ->first();
    }
    if (!empty($savedToken['token'])) {
      return TRUE;
    }
    \Civi\Firewall\Event\InvalidCSRFEvent::trigger(\CRM_Utils_System::ipAddress(), NULL);
    return FALSE;
  }

}
