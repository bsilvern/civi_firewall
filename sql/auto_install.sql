-- +--------------------------------------------------------------------+
-- | Copyright CiviCRM LLC. All rights reserved.                        |
-- |                                                                    |
-- | This work is published under the GNU AGPLv3 license with some      |
-- | permitted exceptions and without any warranty. For full license    |
-- | and copyright information, see https://civicrm.org/licensing       |
-- +--------------------------------------------------------------------+
--
-- Generated from schema.tpl
-- DO NOT EDIT.  Generated by CRM_Core_CodeGen
--
-- /*******************************************************
-- *
-- * Clean up the existing tables
-- *
-- *******************************************************/
SET FOREIGN_KEY_CHECKS=0;
DROP TABLE IF EXISTS `civicrm_firewall_ipaddress`;
SET FOREIGN_KEY_CHECKS=1;
-- /*******************************************************
-- *
-- * Create new tables
-- *
-- *******************************************************/

-- /*******************************************************
-- *
-- * civicrm_firewall_ipaddress
-- *
-- * IP addresses logged by firewall
-- *
-- *******************************************************/
CREATE TABLE `civicrm_firewall_ipaddress` (
  `id` int unsigned NOT NULL AUTO_INCREMENT  COMMENT 'Unique FirewallIpaddress ID',
  `ip_address` varchar(255) NOT NULL   COMMENT 'IP address used',
  `access_date` timestamp NOT NULL  DEFAULT CURRENT_TIMESTAMP COMMENT 'When the IP address accessed',
  `event_type` varchar(64) NOT NULL   COMMENT 'The type of event that triggered this log',
  `source` varchar(255)    COMMENT 'Origin of this access request',
  PRIMARY KEY (`id`),
  INDEX `index_ip_address`(ip_address)
) ENGINE=InnoDB;
