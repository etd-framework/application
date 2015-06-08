<?php
/**
 * Part of the ETD Framework Application Package
 *
 * @copyright   Copyright (C) 2015 ETD Solutions, SARL Etudoo. Tous droits réservés.
 * @license     Apache License 2.0; see LICENSE
 * @author      ETD Solutions http://etd-solutions.com
 */

namespace EtdSolutions\Application;

use EtdSolutions\Language\LanguageFactory;

use Joomla\Application\AbstractDaemonApplication;
use Joomla\Database\DatabaseDriver;
use Joomla\Database\DatabaseFactory;
use Joomla\Input\Cli;
use Joomla\Language\Language;
use Joomla\Language\Text;
use Joomla\Registry\Registry;

use Monolog\Handler\StreamHandler;
use Monolog\Logger;

abstract class Daemon extends AbstractDaemonApplication {

    /**
     * @var  Daemon  L'instance de l'application.
     */
    private static $instance;

    /**
     * @var DatabaseDriver Le gestionnaire de la base de données.
     */
    protected $db;

    /**
     * @var Language La langue de l'application.
     */
    protected $language;

    /**
     * @var Text Le gestionnaire de traduction de l'application.
     */
    protected $text;

    /**
     * Constructeur
     *
     * @param Cli      $input
     * @param Registry $config
     */
    public function __construct(Cli $input = null, Registry $config = null) {

        // On charge la configuration.
        $config = new Registry(new \JConfig());

        parent::__construct($input, $config);

    }

    /**
     * Initialise l'application.
     */
    protected function initialise() {

        // On définit le fuseau horaire.
        @date_default_timezone_set($this->get('timezone', 'Europe/Paris'));

        // On initialise la langue.
        $this->getLanguage();

        // On instancie le logger.
        $logger = new Logger($this->get('application_name'));
        $logger->pushHandler(new StreamHandler(JPATH_LOGS . "/" . $this->get('application_logfile'), $this->get('logger_level')));
        $this->setLogger($logger);

        // PID
        $this->set('application_pid_file', JPATH_TMP . "/" . $this->get('application_pid_file'));

    }

    /**
     * Méthode pour récupérer une instance d'une application, la créant si besoin.
     *
     * @param   string $name Le nom de l'application
     *
     * @return  Daemon  L'instance.
     *
     * @throws   \RuntimeException
     */
    public static function getInstance($name) {

        $name  = ucfirst($name);
        $store = md5($name);

        if (empty(self::$instance[$store])) {

            $conf = new \JConfig;

            $className = $conf->application_namespace . '\\Application\\' . $name . 'Application';

            // On vérifie que l'on a bien une classe valide.
            if (!class_exists($className)) {
                throw new \RuntimeException("Unable find application " . $name, 500);
            }

            self::$instance[$store] = new $className;
        }

        return self::$instance[$store];
    }

    /**
     * Renvoi le gestionnaire de base de données, en le créant s'il n'est pas initialisé.
     *
     * @return DatabaseDriver Le gestionnaire de base de données.
     */
    public function getDb() {

        if (!isset($this->db)) {
            // On initialise la base de données.
            $dbFactory = new DatabaseFactory();

            $this->db = $dbFactory->getDriver($this->get('database.driver'), array(
                'host'     => $this->get('database.host'),
                'user'     => $this->get('database.user'),
                'password' => $this->get('database.password'),
                'port'     => $this->get('database.port'),
                'socket'   => $this->get('database.socket'),
                'database' => $this->get('database.name'),
                'prefix'   => $this->get('database.prefix'),
            ));

            // Debug ?
            if (JDEBUG) {
                $this->db->setDebug(true);
            }

        }

        return $this->db;

    }

    /**
     * Renvoi l'objet de langue.
     *
     * @return  Language
     *
     * @note    JPATH_ROOT doit être définit.
     */
    public function getLanguage() {

        if (is_null($this->language)) {

            $factory = new LanguageFactory;

            // On instancie la langue par défaut.
            $language = $factory->getLanguage($factory->getDefaultLanguage(), JPATH_ROOT, $this->get('debug_language', false));

            if ($this->get('language') != $factory->getDefaultLanguage()) {
                // On récupère l'objet Language avec le tag de langue.
                // On charge aussi le fichier de langue /xx-XX/xx-XX.ini et les fonctions de localisation /xx-XX/xx-XX.localise.php si dispo.
                $language = $factory->getLanguage($this->get('language'), JPATH_ROOT, $this->get('debug_language', false));
            }

            $this->language = $language;
        }

        return $this->language;
    }

    /**
     * Renvoi l'objet de traduction.
     *
     * @return Text
     */
    public function getText() {

        if (is_null($this->text)) {

            $factory = new LanguageFactory;

            // On instancie la classe Text.
            $this->text = $factory->getText($this->getLanguage());
        }

        return $this->text;

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
        $text = $this->getText();

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

        if (isset($this->db)) {
            $this->getDb()
                 ->disconnect();
        }

        parent::shutdown($restart);

    }

}