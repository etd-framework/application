<?php
/**
 * Part of the ETD Framework Application Package
 *
 * @copyright   Copyright (C) 2015 ETD Solutions, SARL Etudoo. Tous droits réservés.
 * @license     Apache License 2.0; see LICENSE
 * @author      ETD Solutions http://etd-solutions.com
 */

namespace EtdSolutions\Application;

use Joomla\DI\Container;
use Joomla\DI\ContainerAwareInterface;
use Joomla\DI\ContainerAwareTrait;
use Joomla\Input\Cli;
use Joomla\Registry\Registry;

use Monolog\Handler\StreamHandler;
use Monolog\Logger;

abstract class Daemon extends AbstractDaemon implements ContainerAwareInterface {

    use ContainerAwareTrait;

    /**
     * Constructeur
     *
     * @param Container $container
     * @param Cli      $input
     * @param Registry $config
     */
    public function __construct(Container $container, Cli $input = null, Registry $config = null) {

        $this->setContainer($container);

        parent::__construct($input, $container->get('config'));

    }

    /**
     * Initialise l'application.
     */
    protected function initialise() {

        // On définit le fuseau horaire.
        @date_default_timezone_set($this->get('timezone', 'Europe/Paris'));

        // On instancie le logger.
        $logger = new Logger($this->get('application_name'));
        $logger->pushHandler(new StreamHandler(JPATH_LOGS . "/" . $this->get('application_logfile'), $this->get('logger_level')));
        $this->setLogger($logger);

        // PID
        $this->set('application_pid_file', JPATH_TMP . "/" . $this->get('application_pid_file'));

    }

    /**
     * Change l'identité du processus.
     *
     * @return  boolean  True si l'identité a été changée avec succès.
     *
     * @see     posix_setuid()
     */
    protected function changeIdentity() {

        // On récupère le traducteur.
        $text = $this->getContainer()->get('language')->getText();

        // Get the group and user ids to set for the daemon.
        $uid = (int)$this->config->get('application_uid', 0);
        $gid = (int)$this->config->get('application_gid', 0);

        // Get the application process id file path.
        $file = $this->config->get('application_pid_file');

        // Change the user id for the process id file if necessary.
        if ($uid && (fileowner($file) != $uid) && (!@ chown($file, $uid))) {
            $this->getLogger()
                 ->error($text->translate('APP_DAEMON_ERROR_ID_FILE_USER_OWNERSHIP'));

            return false;
        }

        // Change the group id for the process id file if necessary.
        if ($gid && (filegroup($file) != $gid) && (!@ chgrp($file, $gid))) {
            $this->getLogger()
                 ->error($text->translate('APP_DAEMON_ERROR_ID_FILE_GROUP_OWNERSHIP'));

            return false;
        }

        // Set the correct home directory for the process.
        if ($uid && ($info = posix_getpwuid($uid)) && is_dir($info['dir'])) {
            system('export HOME="' . $info['dir'] . '"');
        }

        // Change the group id for the process necessary.
        if ($gid && (posix_getgid() != $gid) && (!@ posix_setgid($gid))) {
            $this->getLogger()
                 ->error($text->translate('APP_DAEMON_ERROR_ID_PROCESS_GROUP_OWNERSHIP'));

            return false;
        }

        // Change the user id for the process necessary.
        if ($uid && (posix_getuid() != $uid) && (!@ posix_setuid($uid))) {
            $this->getLogger()
                 ->error($text->translate('APP_DAEMON_ERROR_ID_PROCESS_USER_OWNERSHIP'));

            return false;
        }

        // Get the user and group information based on uid and gid.
        $user  = posix_getpwuid($uid);
        $group = posix_getgrgid($gid);

        $this->getLogger()
             ->info($text->sprintf('APP_DAEMON_ID_SUCCESS', $user['name'], $group['name']));

        return true;
    }

    /**
     * Méthode pour éteindre le daemon et optionnellement le redémarrer.
     *
     * @param   boolean $restart True pour redémarrer le daemon en sortie.
     *
     * @return  void
     */
    protected function shutdown($restart = false) {

        $this->getContainer()->get('db')
             ->disconnect();

        parent::shutdown($restart);

    }

}