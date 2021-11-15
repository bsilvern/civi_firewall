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

use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;

/**
 * Services
 *
 * Define the services
 */
class Services {

  public static function registerServices(ContainerBuilder $container) {
    $container->addResource(new \Symfony\Component\Config\Resource\FileResource(__FILE__));
    $container
      ->setDefinition('firewall_fraudulent_request', new Definition('\Civi\Firewall\Listener\FraudulentRequest'))
      ->setPublic(TRUE);
    $container
      ->setDefinition('firewall_invalidcsrf_request', new Definition('\Civi\Firewall\Listener\InvalidCSRFRequest'))
      ->setPublic(TRUE);

    foreach (self::getListenerSpecs() as $listenerSpec) {
      $container->findDefinition('dispatcher')->addMethodCall('addListenerService', $listenerSpec);
    }
  }

  protected static function getListenerSpecs() {
    $listenerSpecs = [
      ['civi.firewall.fraud', ['firewall_fraudulent_request', 'onTrigger'], 2000],
      ['civi.firewall.invalidcsrf', ['firewall_invalidcsrf_request', 'onTrigger'], 2000],
    ];
    return $listenerSpecs;
  }

}
