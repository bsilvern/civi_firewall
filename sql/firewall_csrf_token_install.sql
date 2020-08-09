-- +--------------------------------------------------------------------+
-- | Copyright CiviCRM LLC. All rights reserved.                        |
-- |                                                                    |
-- | This work is published under the GNU AGPLv3 license with some      |
-- | permitted exceptions and without any warranty. For full license    |
-- | and copyright information, see https://civicrm.org/licensing       |
-- +--------------------------------------------------------------------+

SET FOREIGN_KEY_CHECKS=0;
DROP TABLE IF EXISTS `civicrm_firewall_csrf_token`;
SET FOREIGN_KEY_CHECKS=1;

-- /*******************************************************
-- *
-- * civicrm_firewall_csrf_token
-- *
-- * CSRF Tokens issued by firewall extension
-- *
-- *******************************************************/
CREATE TABLE `civicrm_firewall_csrf_token` (
     `id` int unsigned NOT NULL AUTO_INCREMENT  COMMENT 'Unique FirewallCsrfToken ID',
     `created_date` timestamp NOT NULL  DEFAULT CURRENT_TIMESTAMP COMMENT 'When the token was created',
     `token` varchar(255)    COMMENT 'The CSRF token',
     `source` varchar(255)    COMMENT 'Source of this CSRF token',
     PRIMARY KEY (`id`)
) ENGINE=InnoDB;
