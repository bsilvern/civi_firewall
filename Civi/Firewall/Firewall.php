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

use CRM_Firewall_ExtensionUtil as E;

class Firewall {

  /**
   * The "reason" why a request was blocked or a token was invalid.
   *
   * @var string
   */
  private $reason = '';

  /**
   * The user friendly, translateable description for the reason
   *
   * @var string
   */
  private $reasonDescription = '';

  /**
   * The client IP address
   *
   * @var string
   */
  private $clientIP;

  /**
   * @return string
   */
  public function getReason(): string {
    return $this->reason;
  }

  /**
   * @param string $reason
   */
  private function setReason(string $reason) {
    $this->reason = $reason;
    switch ($reason) {
      case 'expiredcsrf':
        $this->setReasonDescription(E::ts('Session expired. Please reload and try again.'));
        break;

      case 'invalidcsrf':
      case 'tamperedcsrf':
        // Be careful not to give out too much information that could help someone bypass the CSRF check.
        $this->setReasonDescription(E::ts('Session invalid. Please reload and try again.'));
        break;

      case 'blockedfraud':
      case 'blockedinvalidcsrf':
      case 'blockedblocklist':
      default:
        $this->setReasonDescription(E::ts('Blocked'));
    }
  }

  /**
   * Get the description for the reason
   *
   * @return string
   */
  public function getReasonDescription(): string {
    return $this->reasonDescription;
  }

  /**
   * Set the description for the reason
   *
   * @param string $reasonDescription
   */
  private function setReasonDescription(string $reasonDescription) {
    $this->reasonDescription = $reasonDescription;
  }

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
    $this->setReason('');
    // @todo make these settings configurable.
    // If there are more than COUNT triggers for this event within time interval then block
    $interval = 'INTERVAL 2 HOUR';
    $this->clientIP = $this->getIPAddress();
    if (!isset($this->clientIP)) {
      return FALSE;
    }

    if ($this->isClientIPOnSafelist()) {
      return FALSE;
    }

    if ($this->isClientIPOnBlocklist()) {
      return TRUE;
    }

    $queryParams = [
      // The client IP address
      1 => [$this->clientIP, 'String'],
    ];


    //block only contribution-related requests
    $url_transact = $_SERVER['SCRIPT_URL'] == '/drupal/civicrm/contribute/transact'; //includes GETs and POSTs
    $post_rest = $_SERVER['SCRIPT_URL'] == '/drupal/civicrm/ajax/rest' && ($_POST['entity'] ?? '') == 'StripePaymentintent';
    if (!$url_transact && !$post_rest) {
      return FALSE; //not contribution related
    } 

    function email_notify($state) {
      $tpl_params['subject'] = "Card Tester Status: $state";
      $tpl_params['body'] = 'Sent by firewall/Civi/Firewall/Firewall.php';
      $ret = \CRM_Core_BAO_MessageTemplate::sendTemplate([
        'tplParams' => $tpl_params, //array of smarty variables (tokens): include in email as {$variable_name}

        //USER-SPECIFIC DETAILS
        //'messageTemplateID' => ***, //specify a suitable template number
        //'toEmail' => '***',
        //'toName' => '***', 
        //'from' => '***',
      ]);
    }

    //Test if we are under attack (if Stipe failures during $failed_lookback_period exceed $failed_threshold)
    $card_tester_active = \Civi::settings()->get('card_tester_active');
    $failed_lookback_period = "INTERVAL 12 HOUR";
    $failed_threshold = 10;
    $sql = "
      SELECT COUNT(id) failed_count FROM civicrm_stripe_paymentintent 
      WHERE created_date >= DATE_SUB(NOW(), $failed_lookback_period) AND status = 'failed';";
    $failed_count = \CRM_Core_DAO::singleValueQuery($sql);
    if ($failed_count > $failed_threshold) {
      //Number of recent failed Stripe transactions is over threshold. Looks like we're under attack, so we'll:
      //  Decrease the failure thresholds for blocking
      //  Increase the lookback interval for failures
      $blockFraudAfter = 2;
      $blockInvalidCSRFAfter = 2;
      $blockOtherAfter = 2;
      $interval = 'INTERVAL 24 HOUR';
      if (!$card_tester_active) {
        \Civi::settings()->set('card_tester_active', "1");
        \Civi::settings()->set('forceRecaptcha', "1");
        email_notify('Active');
      }
    } else {
      $blockFraudAfter = 5;
      $blockInvalidCSRFAfter = 5;
      $blockOtherAfter = 20;
      if ($card_tester_active) {
        \Civi::settings()->set('card_tester_active', "0");
        \Civi::settings()->set('forceRecaptcha', "0");
        email_notify('Inactive');
      }
    }


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
            $this->setReason('blockedfraud');
            break 2;
          }
          break;

        case 'InvalidCSRFEvent':
          if ($dao->eventCount >= $blockInvalidCSRFAfter) {
            $block = TRUE;
            $this->setReason('blockedinvalidcsrf');
            break 2;
          }
          break;

        
        //Block IPs which had excessive declined payments due to any other reason (commonly 'generic_decline')
        default: 
          if ($dao->eventCount >= $blockOtherAfter) {
            $block = TRUE;
            $this->setReason('blockedother');
            break 2;
          }
          break;
      }
    }
    return $block;
  }

  /**
   * Given a list of IP addresses (optionally including wildcards eg. 192.* or 192.168.* or 192.168.11.*)
   * Currently only supports ipv4 addresses
   *
   * @param array $ipAddresses
   *
   * @return bool
   */
  private function isWildcardIPV4Match(array $ipAddresses): bool {
    $ipv4 = (strpos($this->clientIP, '.') !== FALSE);

    if ($ipv4) {
      $parts = explode(".", $this->clientIP);
      $wilds = [
        sprintf('%s.*', $parts[0]),
      ];
      if (!empty($parts[1])) {
        $wilds[] = sprintf('%s.%s.*', $parts[0], $parts[1]);
      }
      if (!empty($parts[2])) {
        $wilds[] = sprintf('%s.%s.%s.*', $parts[0], $parts[1], $parts[2]);
      }
      if ((bool) array_intersect($wilds, $ipAddresses)) {
        return TRUE;
      }
    }
    return FALSE;
  }

  /**
   * Does the client IP match a Safelist address? Can include wildcards for ipv4
   *
   * @return bool
   */
  private function isClientIPOnSafelist(): bool {
    $safelistIPAddresses = explode(',', \Civi::settings()->get('firewall_whitelist_addresses'));
    if (in_array($this->clientIP, $safelistIPAddresses) || $this->isWildcardIPV4Match($safelistIPAddresses)) {
      return TRUE;
    }
    return FALSE;
  }

  /**
   * Does the client IP match a Blocklist address? Can include wildcards for ipv4
   *
   * @return bool
   */
  private function isClientIPOnBlocklist(): bool {
    $blocklistIPAddresses = explode(',', \Civi::settings()->get('firewall_blocklist_addresses'));
    if (in_array($this->clientIP, $blocklistIPAddresses) || $this->isWildcardIPV4Match($blocklistIPAddresses)) {
      $this->setReason('blockedblocklist');
      return TRUE;
    }
    return FALSE;
  }

  /**
   * Generate a CSRF token. Clients will need to retrieve and pass this into AJAX/API requests.
   *
   * @return string
   * @throws \Exception
   */
  public static function getCSRFToken(): string {
    $firewall = new Firewall();
    return $firewall->generateCSRFToken();
  }

  /**
   * Generate a CSRF token. Clients will need to retrieve and pass this into AJAX/API requests.
   *
   * @return string
   * @throws \Exception
   */
  public function generateCSRFToken(): string {
    //Apply CSRF expiration time when it is checked rather than when it is generated
    $validTo = time();
    $random = bin2hex(random_bytes(12));
    $privateKey = CIVICRM_SITE_KEY;

    $publicToken = "$validTo.$random.";
    $dataToHash = $publicToken . $privateKey;

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
    $firewall = new Firewall();
    return $firewall->checkIsCSRFTokenValid($givenToken);
  }

  /**
   * Check if the passed in CSRF token is valid and trigger InvalidCSRFEvent if invalid.
   *
   * @param string $givenToken
   *
   * @return bool
   */
  public function checkIsCSRFTokenValid(string $givenToken): bool {
    $this->setReason('');
    if (!preg_match('/^(\d+)\.([a-f0-9]+)\.([a-f0-9]+)$/', $givenToken, $matches)) {
      \Civi\Firewall\Event\InvalidCSRFEvent::trigger($this->getIPAddress(), 'invalid token');
      $this->setReason('invalidcsrf');
      return FALSE;
    }
    //Reduce CSRF timeout if we're under attack
    $card_tester_active = \Civi::settings()->get('card_tester_active');
    $timeout = $card_tester_active ? 1800 : (int)\Civi::settings()->get('firewall_csrf_timeout');  
    if (time() > ($matches[1] + $timeout)) {
      \Civi\Firewall\Event\InvalidCSRFEvent::trigger($this->getIPAddress(), 'expired token');
      $this->setReason('expiredcsrf');
      return FALSE;
    }
    $dataToHash = "$matches[1].$matches[2]." . CIVICRM_SITE_KEY;
    if ($matches[3] !== hash('sha256', $dataToHash)) {
      \Civi\Firewall\Event\InvalidCSRFEvent::trigger($this->getIPAddress(), 'tampered hash');
      $this->setReason('tamperedcsrf');
      return FALSE;
    }
    // OK to continue...
    return TRUE;
  }

  /**
   * Get the IP address of the client. Based on the Drupal function. Support for reverse proxies and Safelists.
   *
   * @return string
   */
  public function getIPAddress(): string {
    if (!isset(\Civi::$statics[__CLASS__]['ipAddress'])) {
      $ipAddress = $_SERVER['REMOTE_ADDR'] ?? '';

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
