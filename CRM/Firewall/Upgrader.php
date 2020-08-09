<?php
use CRM_Firewall_ExtensionUtil as E;

/**
 * Collection of upgrade steps.
 */
class CRM_Firewall_Upgrader extends CRM_Firewall_Upgrader_Base {

  /**
   * Example: Run a couple simple queries.
   *
   * @return TRUE on success
   * @throws Exception
   */
  public function upgrade_1000() {
    $this->ctx->log->info('Applying update 1000 - create civicrm_firewall_csrf_token table');
    if (!CRM_Core_DAO::checkTableExists('civicrm_firewall_csrf_token')) {
      $this->executeSqlFile('sql/firewall_csrf_token_install.sql');
    }
    return TRUE;
  }

}
