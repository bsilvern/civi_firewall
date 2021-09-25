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
  public function shouldThisRequestBeBlocked(): bool {
    // @todo make these settings configurable.
    // If there are more than COUNT triggers for this event within time interval then block
    $interval = 'INTERVAL 2 HOUR';
    $clientIP = Firewall::getIPAddress();
    if (!isset($clientIP)) {
      return FALSE;
    }
    $whitelistIPAddresses = explode(',', \Civi::settings()->get('firewall_whitelist_addresses'));
    if (in_array($clientIP, $whitelistIPAddresses)) {
      return FALSE;
    }

    $queryParams = [
      // The client IP address
      1 => [$clientIP, 'String'],
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
    $validTo = time() + (int) \Civi::settings()->get('firewall_csrf_timeout');
    $random = bin2hex(random_bytes(12));
    $privateKey = CIVICRM_SITE_KEY;

    $publicToken = "$validTo.$random.";
    $dataToHash = $publicToken . $privateKey;

    $dataToHash .= Firewall::getIPAddress();

    // This is the token that we send to the browser, that it must send back.
    $publicToken .= hash('sha256', $dataToHash);
    return $publicToken;
  }

  /**
   * Check if the passed in CSRF token is valid and trigger InvalidCSRFEvent if invalid.
   *
   * @param string $givenToken
   *
   * @return bool
   */
  public static function isCSRFTokenValid(string $givenToken): bool {
    if (!preg_match('/^(\d+)\.([a-f0-9]+)\.([a-f0-9]+)$/', $givenToken, $matches)) {
      \Civi\Firewall\Event\InvalidCSRFEvent::trigger(Firewall::getIPAddress(), 'invalid token');
      return FALSE;
    }
    if (time() > $matches[1]) {
      \Civi\Firewall\Event\InvalidCSRFEvent::trigger(Firewall::getIPAddress(), 'expired token');
      return FALSE;
    }
    $dataToHash = "$matches[1].$matches[2]." . CIVICRM_SITE_KEY;
    $dataToHash .= Firewall::getIPAddress();
    if ($matches[3] !== hash('sha256', $dataToHash)) {
      \Civi\Firewall\Event\InvalidCSRFEvent::trigger(Firewall::getIPAddress(), 'tampered hash');
      return FALSE;
    }
    // OK to continue...
    return TRUE;
  }

  public static function getIPAddress() {
    if (!isset(\Civi::$statics[__CLASS__]['ipAddress'])) {
      $ipAddress = $_SERVER['REMOTE_ADDR'];

      if (\Civi::settings()->get('firewall_reverse_proxy')) {
        $reverseProxyHeader = \Civi::settings()->get('firewall_reverse_proxy_header');
        if (!empty($_SERVER[$reverseProxyHeader])) {
          // If an array of known reverse proxy IPs is provided, then trust
          // the XFF header if request really comes from one of them.
          $reverseProxyAddresses = explode(',', \Civi::settings()->get('firewall_reverse_proxy_addresses'));

          // Turn XFF header into an array.
          $forwarded = explode(',', $_SERVER[$reverseProxyHeader]);

          // Trim the forwarded IPs; they may have been delimited by commas and spaces.
          $forwarded = array_map('trim', $forwarded);

          // Tack direct client IP onto end of forwarded array.
          $forwarded[] = $ipAddress;

          // Eliminate all trusted IPs.
          $untrusted = array_diff($forwarded, $reverseProxyAddresses);

          if (!empty($untrusted)) {
            // The right-most IP is the most specific we can trust.
            $ipAddress = array_pop($untrusted);
          }
          else {
            // All IP addresses in the forwarded array are configured proxy IPs
            // (and thus trusted). We take the leftmost IP.
            $ipAddress = array_shift($forwarded);
          }
        }
      }
      \Civi::$statics[__CLASS__]['ipAddress'] = $ipAddress;
    }

    return \Civi::$statics[__CLASS__]['ipAddress'];
  }

}
