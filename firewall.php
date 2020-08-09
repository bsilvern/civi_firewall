<?php

require_once 'firewall.civix.php';
use CRM_Firewall_ExtensionUtil as E;

/**
 * Implements hook_civicrm_config().
 *
 * @link https://docs.civicrm.org/dev/en/latest/hooks/hook_civicrm_config/
 */
function firewall_civicrm_config(&$config) {
  $firewall = new \Civi\Firewall\Firewall();
  $firewall->run();
  _firewall_civix_civicrm_config($config);
}

/**
 * Implements hook_civicrm_container().
 */
function firewall_civicrm_container(\Symfony\Component\DependencyInjection\ContainerBuilder $container) {
  $container->addResource(new \Symfony\Component\Config\Resource\FileResource(__FILE__));
  \Civi\Firewall\Services::registerServices($container);
}

/**
 * Implements hook_civicrm_xmlMenu().
 *
 * @link https://docs.civicrm.org/dev/en/latest/hooks/hook_civicrm_xmlMenu
 */
function firewall_civicrm_xmlMenu(&$files) {
  _firewall_civix_civicrm_xmlMenu($files);
}

/**
 * Implements hook_civicrm_install().
 *
 * @link https://docs.civicrm.org/dev/en/latest/hooks/hook_civicrm_install
 */
function firewall_civicrm_install() {
  _firewall_civix_civicrm_install();
}

/**
 * Implements hook_civicrm_postInstall().
 *
 * @link https://docs.civicrm.org/dev/en/latest/hooks/hook_civicrm_postInstall
 */
function firewall_civicrm_postInstall() {
  _firewall_civix_civicrm_postInstall();
}

/**
 * Implements hook_civicrm_uninstall().
 *
 * @link https://docs.civicrm.org/dev/en/latest/hooks/hook_civicrm_uninstall
 */
function firewall_civicrm_uninstall() {
  _firewall_civix_civicrm_uninstall();
}

/**
 * Implements hook_civicrm_enable().
 *
 * @link https://docs.civicrm.org/dev/en/latest/hooks/hook_civicrm_enable
 */
function firewall_civicrm_enable() {
  _firewall_civix_civicrm_enable();
}

/**
 * Implements hook_civicrm_disable().
 *
 * @link https://docs.civicrm.org/dev/en/latest/hooks/hook_civicrm_disable
 */
function firewall_civicrm_disable() {
  _firewall_civix_civicrm_disable();
}

/**
 * Implements hook_civicrm_upgrade().
 *
 * @link https://docs.civicrm.org/dev/en/latest/hooks/hook_civicrm_upgrade
 */
function firewall_civicrm_upgrade($op, CRM_Queue_Queue $queue = NULL) {
  return _firewall_civix_civicrm_upgrade($op, $queue);
}

/**
 * Implements hook_civicrm_managed().
 *
 * Generate a list of entities to create/deactivate/delete when this module
 * is installed, disabled, uninstalled.
 *
 * @link https://docs.civicrm.org/dev/en/latest/hooks/hook_civicrm_managed
 */
function firewall_civicrm_managed(&$entities) {
  _firewall_civix_civicrm_managed($entities);
}

/**
 * Implements hook_civicrm_angularModules().
 *
 * Generate a list of Angular modules.
 *
 * Note: This hook only runs in CiviCRM 4.5+. It may
 * use features only available in v4.6+.
 *
 * @link https://docs.civicrm.org/dev/en/latest/hooks/hook_civicrm_angularModules
 */
function firewall_civicrm_angularModules(&$angularModules) {
  _firewall_civix_civicrm_angularModules($angularModules);
}

/**
 * Implements hook_civicrm_alterSettingsFolders().
 *
 * @link https://docs.civicrm.org/dev/en/latest/hooks/hook_civicrm_alterSettingsFolders
 */
function firewall_civicrm_alterSettingsFolders(&$metaDataFolders = NULL) {
  _firewall_civix_civicrm_alterSettingsFolders($metaDataFolders);
}

/**
 * Implements hook_civicrm_entityTypes().
 *
 * Declare entity types provided by this module.
 *
 * @link https://docs.civicrm.org/dev/en/latest/hooks/hook_civicrm_entityTypes
 */
function firewall_civicrm_entityTypes(&$entityTypes) {
  _firewall_civix_civicrm_entityTypes($entityTypes);
}

/**
 * Implements hook_civicrm_alterLogTables().
 *
 * Exclude firewall tables from logging tables since they hold mostly temp data.
 */
function firewall_civicrm_alterLogTables(&$logTableSpec) {
  $tablePrefix = 'civicrm_firewall_';
  $len = strlen($tablePrefix);

  foreach ($logTableSpec as $key => $val) {
    if (substr($key, 0, $len) === $tablePrefix) {
      unset($logTableSpec[$key]);
    }
  }
}
