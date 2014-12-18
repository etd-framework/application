<?php
/**
 * @package     etd-framework
 *
 * @version     0.0.1
 * @copyright   Copyright (C) 2014 ETD Solutions, SARL Etudoo. Tous droits réservés.
 * @license     http://etd-solutions.com/LICENSE
 * @author      ETD Solutions http://etd-solutions.com
 */

namespace EtdSolutions\Framework\Application;

use EtdSolutions\Framework\Controller\ErrorController;
use EtdSolutions\Framework\Document\Document;
use EtdSolutions\Framework\User\User;
use Joomla\Application\AbstractWebApplication;
use Joomla\Crypt\Password\Simple;
use Joomla\Database\DatabaseFactory;
use Joomla\Database\DatabaseDriver;
use Joomla\Filter\InputFilter;
use Joomla\Language\Language;
use Joomla\Language\Text;
use Joomla\Registry\Registry;
use Joomla\Input\Input;
use Joomla\Application\Web\WebClient;
use EtdSolutions\Framework\Session\Session;
use Joomla\Router\Router;
use Joomla\Uri\Uri;
use Joomla\String\String;
use Monolog\Handler\NullHandler;
use Monolog\Handler\StreamHandler;
use Monolog\Logger;

defined('_JEXEC') or die;

final class Web extends AbstractWebApplication {

    /**
     * @var Router  Le router de l'application.
     */
    public $router;

    /**
     * @var Language La langue de l'application.
     */
    protected $language;

    /**
     * @var array Liste des messages devant être affichés à l'utilisateur.
     */
    protected $_messageQueue = array();

    /**
     * @var DatabaseDriver Le gestionnaire de la base de données.
     */
    protected $db;

    /**
     * @var array Dernière erreur.
     */
    protected $error;

    /**
     * @var string Nom du controller actif dans l'application.
     */
    protected $_activeController = '';

    /**
     * @var  Web  L'instance de l'application.
     */
    private static $instance;

    public function __construct(Input $input = null, Registry $config = null, WebClient $client = null) {

        // On charge la configuration.
        $config = new Registry(new \JConfig());

        parent::__construct($input, $config, $client);

    }

    /**
     * Retourne l'input
     *
     * @return \Joomla\Input\Input
     */
    public function getInput() {

        return $this->input;
    }

    /**
     * Retourne une référence à l'objet global Web, en le créant seulement si besoin.
     *
     * @return  Web
     */
    public static function getInstance() {

        if (empty(self::$instance)) {
            self::$instance = new Web;
        }

        return self::$instance;
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

            // Logger
            $this->db->setLogger($this->getLogger());

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

            // On récupère l'objet Language avec le tag de langue.
            // On charge aussi le fichier de langue /xx-XX/xx-XX.ini et les fonctions de localisation /xx-XX/xx-XX.localise.php si dispo.
            $language = Language::getInstance($this->get('language'), $this->get('debug_language', false));

            // On configure Text pour utiliser notre instance de Language.
            Text::setLanguage($language);

            $this->language = $language;
        }

        return $this->language;
    }

    /**
     * Renvoi le document.
     *
     * @return Document
     *
     * @note Juste un proxy vers Document::getInstance
     */
    public function getDocument() {

        return Document::getInstance();
    }

    /**
     * Contrôle un jeton de formulaire dans la requête.
     *
     * A utiliser avec getFormToken.
     *
     * @param   string $method La méthode de la requête dans la laquelle on doit trouver le jeton.
     *
     * @return  boolean  True si trouvé et valide, false sinon.
     */
    public function checkToken($method = 'request') {

        $token = $this->getFormToken();

        if (!$this->input->$method->get($token, '', 'alnum')) {
            if ($this->getSession()
                     ->isNew()
            ) {
                // On redirige vers la page de login.
                $this->redirect('login', Text::_('APP_ERROR_EXPIRED_SESSION'), 'warning');
            } else {
                return false;
            }
        } else {
            return true;
        }
    }

    /**
     * Redirige le navigateur vers une nouvelle adresse.
     *
     * @param string $url     La nouvelle URL
     * @param string $msg     Message a afficher à l'utilisateur
     * @param string $msgType Type du message
     * @param bool   $moved   Redirection 301 pour indiquer une page qui a changé d'emplacement (SEF)
     */
    public function redirect($url, $msg = '', $msgType = 'message', $moved = false) {

        // Check for relative internal links.
        if (preg_match('#^index\.php#', $url)) {
            $url = $this->get('uri.base.full') . $url;
        }

        // Perform a basic sanity check to make sure we don't have any CRLF garbage.
        $url = preg_split("/[\r\n]/", $url);
        $url = $url[0];

        /*
         * Here we need to check and see if the URL is relative or absolute.  Essentially, do we need to
         * prepend the URL with our base URL for a proper redirect.  The rudimentary way we are looking
         * at this is to simply check whether or not the URL string has a valid scheme or not.
         */
        if (!preg_match('#^[a-z]+\://#i', $url)) {
            // Get a JURI instance for the requested URI.
            $uri = new Uri($this->get('uri.request'));

            // Get a base URL to prepend from the requested URI.
            $prefix = $uri->toString(array(
                'scheme',
                'user',
                'pass',
                'host',
                'port'
            ));

            // We just need the prefix since we have a path relative to the root.
            if ($url[0] == '/') {
                $url = $prefix . $url;
            } else // It's relative to where we are now, so lets add that.
            {
                $parts = explode('/', $uri->toString(array('path')));
                array_pop($parts);
                $path = implode('/', $parts) . '/';
                $url  = $prefix . $path . $url;
            }
        }

        // If the message exists, enqueue it.
        if (trim($msg)) {
            $this->enqueueMessage($msg, $msgType);
        }

        // Persist messages if they exist.
        if (count($this->_messageQueue)) {
            $session = $this->getSession();
            $session->set('application.queue', $this->_messageQueue);
        }

        // If the headers have already been sent we need to send the redirect statement via JavaScript.
        if ($this->checkHeadersSent()) {
            echo "<script>document.location.href='$url';</script>\n";
        } else {
            // We have to use a JavaScript redirect here because MSIE doesn't play nice with utf-8 URLs.
            if (($this->client->engine == WebClient::TRIDENT) && !String::is_ascii($url)) {
                $html = '<html><head>';
                $html .= '<meta http-equiv="content-type" content="text/html; charset=' . $this->charSet . '" />';
                $html .= '<script>document.location.href=\'' . $url . '\';</script>';
                $html .= '</head><body></body></html>';

                echo $html;
            } else {
                // All other cases use the more efficient HTTP header for redirection.
                $this->header($moved ? 'HTTP/1.1 301 Moved Permanently' : 'HTTP/1.1 303 See other');
                $this->header('Location: ' . $url);
                $this->header('Content-Type: text/html; charset=' . $this->charSet);
            }
        }

        // Close the application after the redirect.
        $this->close();
    }

    public function enqueueMessage($msg, $type = 'info') {

        if (!count($this->_messageQueue)) {
            $session      = $this->getSession();
            $sessionQueue = $session->get('application.queue');

            if (count($sessionQueue)) {
                $this->_messageQueue = $sessionQueue;
                $session->set('application.queue', null);
            }
        }

        // Enqueue the message.
        $type = strtolower($type);
        switch ($type) {
            case 'warning':
                $icon = 'exclamation-circle';
                break;
            case 'danger':
            case 'error':
                $type = 'danger';
                $icon = 'times-circle';
                break;
            case 'success':
                $icon = 'check-circle';
                break;
            case 'info':
            default:
                $type = 'info';
                $icon = 'info-circle';
                break;
        }
        $this->_messageQueue[] = array(
            'message' => $msg,
            'type'    => $type,
            'icon'    => $icon
        );

        return $this;
    }

    /**
     * Get the system message queue.
     *
     * @return  array  The system message queue.
     */
    public function getMessageQueue() {

        // For empty queue, if messages exists in the session, enqueue them.
        if (!count($this->_messageQueue)) {
            $session      = $this->getSession();
            $sessionQueue = $session->get('application.queue');

            if (count($sessionQueue)) {
                $this->_messageQueue = $sessionQueue;
                $session->set('application.queue', null);
            }
        }

        return $this->_messageQueue;
    }

    /**
     * Méthode pour définit une erreur dans l'application.
     *
     * @param string     $message
     * @param int        $code
     * @param \Exception $exception
     */
    public function setError($message, $code, $exception = null) {

        $trace = null;
        $extra = "";

        if (JDEBUG) {
            if (isset($exception)) {
                $trace = $exception->getTrace();
                $extra = str_replace(JPATH_ROOT, "", $exception->getFile()) . ":" . $exception->getLine();
            } else {
                $trace = array_slice(debug_backtrace(), 2);
            }
        }

        $this->error = array(
            'message'   => $message,
            'code'      => $code,
            'backtrace' => $trace,
            'extra'     => $extra
        );
    }

    /**
     * Retourne la dernière erreur enregistrée.
     *
     * @return array    L'erreur
     */
    public function getError() {

        return $this->error;
    }

    public function getActiveController() {

        return $this->_activeController;
    }

    /**
     * Méthode pour déclencher une erreur.
     * On arrête le flux et on affiche la page d'erreur.
     *
     * @param string     $message   Message d'erreur à afficher.
     * @param int        $code      Code de l'erreur.
     * @param \Exception $exception L'exception déclenchée si disponible.
     */
    public function raiseError($message, $code = 500, $exception = null) {

        $this->clearHeaders();
        switch ($code) {
            case 401:
                $status = '401 Unauthorized';
                break;
            case 403:
                $status = '403 Forbidden';
                break;
            case 404:
                $status = '404 Not found';
                break;
            case 500:
                $status = '500 Internal Server Error';
                break;
            default:
                $status = '200 OK';
                break;
        }
        $this->setHeader('status', $status);
        $this->setError($message, $code, $exception);
        $controller = new ErrorController();
        $this->input->set('layout', 'default');
        $this->setBody($controller->execute());
        $this->respond();
        $this->close();
    }

    /**
     * Donne l'état de l'utilisateur.
     *
     * @param   string $key     Le chemin dans l'état.
     * @param   mixed  $default Valeur par défaut optionnelle, retournée si la valeur est null.
     *
     * @return  mixed  L'état ou null.
     */
    public function getUserState($key, $default = null) {

        $session  = $this->getSession();
        $registry = $session->get('state');

        if (!is_null($registry)) {
            return $registry->get($key, $default);
        }

        return $default;
    }

    /**
     * Donne la valeur d'une variable de l'état de l'utilisateur.
     *
     * @param   string $key     La clé de la variable.
     * @param   string $request Le nom de la varaible passée dans la requête.
     * @param   string $default La valeur par défaut de la variale si non trouvée. Optionnel.
     * @param   string $type    Filtre pour la variable. Optionnel.
     *
     * @return  object  L'état.
     */
    public function getUserStateFromRequest($key, $request, $default = null, $type = 'none') {

        $cur_state = $this->getUserState($key, $default);
        $new_state = $this->input->get($request, null, $type);

        // Save the new value only if it was set in this request.
        if ($new_state !== null) {
            $this->setUserState($key, $new_state);
        } else {
            $new_state = $cur_state;
        }

        return $new_state;
    }

    /**
     * Définit la valeur d'une variable de l'état utilisateur.
     *
     * @param   string $key   Le chemin dans l'état.
     * @param   string $value La valeur de la variable.
     *
     * @return  mixed  L'état précédent s'il existe.
     */
    public function setUserState($key, $value) {

        $session  = $this->getSession();
        $registry = $session->get('state');

        if (!is_null($registry)) {
            return $registry->set($key, $value);
        }

        return null;
    }

    /**
     * Méthode d'authentification lors de la connexion.
     *
     * @param   array  $credentials  Array('username' => string, 'password' => string)
     * @param   array  $options      Array('remember' => boolean)
     *
     * @return  boolean  True en cas de succès.
     */
    public function login($credentials, $options = array()) {

        // Si on a demandé l'authentification par cookie.
        if (isset($options['useCookie']) && $options['useCookie']) {

            // On récupère le cookie.
            $cookieName  = $this->getShortHashedUserAgent();
            $cookieValue = $this->input->cookie->get($cookieName);

            if (!$cookieValue) {

                if (!isset($options['silent']) || !$options['silent']) {
                    $this->enqueueMessage(Text::_("APP_ERROR_LOGIN_INVALID_COOKIE"), "danger");
                }

                return false;
            }

            $cookieArray = explode('.', $cookieValue);

            // On contrôle que le cookie est valide.
            if (count($cookieArray) != 2) {

                // On détruit le cookie dans le navigateur.
                $this->input->cookie->set($cookieName, false, time() - 42000, $this->get('cookie_path', '/'), $this->get('cookie_domain'));

                if (!isset($options['silent']) || !$options['silent']) {
                    $this->enqueueMessage(Text::_("APP_ERROR_LOGIN_INVALID_COOKIE"), "danger");
                }

                return false;
            }

            // On filtre les entrées car on va les utiliser dans la requête.
            $filter	= new InputFilter;
            $series	= $filter->clean($cookieArray[1], 'ALNUM');

            // On retire les jetons expirés.
            $query = $this->db->getQuery(true)
                ->delete('#__user_keys')
                ->where($this->db->quoteName('time') . ' < ' . $this->db->quote(time()));
            $this->db->setQuery($query)->execute();

            // On trouve un enregistrement correspondant s'il existe.
            $query = $this->db->getQuery(true)
                ->select($this->db->quoteName(array('user_id', 'token', 'series', 'time')))
                ->from($this->db->quoteName('#__user_keys'))
                ->where($this->db->quoteName('series') . ' = ' . $this->db->quote($series))
                ->where($this->db->quoteName('uastring') . ' = ' . $this->db->quote($cookieName))
                ->order($this->db->quoteName('time') . ' DESC');
            $results = $this->db->setQuery($query)->loadObjectList();

            if (count($results) !== 1) {

                // On détruit le cookie dans le navigateur.
                $this->input->cookie->set($cookieName, false, time() - 42000, $this->get('cookie_path', '/'), $this->get('cookie_domain'));

                if (!isset($options['silent']) || !$options['silent']) {
                    $this->enqueueMessage(Text::_("APP_ERROR_LOGIN_INVALID_COOKIE"), "danger");
                }

                return false;
            } else { // On a un utilisateur avec un cookie valide qui correspond à un enregistrement en base.

                // On instancie la mécanique de vérification.
                $simpleAuth = new Simple();

                //$token = $simpleAuth->create($cookieArray[0]);

                if (!$simpleAuth->verify($cookieArray[0], $results[0]->token)) {

                    // C'est une attaque réelle ! Soit on a réussi à créer un cookie valide ou alors on a volé le cookie et utilisé deux fois (une fois par le pirate et une fois par la victime).
                    // On supprime tous les jetons pour cet utilisateur !
                    $query = $this->db->getQuery(true)
                        ->delete('#__user_keys')
                        ->where($this->db->quoteName('user_id') . ' = ' . $this->db->quote($results[0]->user_id));
                    $this->db->setQuery($query)->execute();

                    // On détruit le cookie dans le navigateur.
                    $this->input->cookie->set($cookieName, false, time() - 42000, $this->get('cookie_path', '/'), $this->get('cookie_domain'));

                    //@TODO: logguer l'attaque et envoyer un mail à l'admin.

                    if (!isset($options['silent']) || !$options['silent']) {
                        $this->enqueueMessage(Text::_("APP_ERROR_LOGIN_INVALID_COOKIE"), "danger");
                    }

                    return false;
                }
            }

            // On s'assure qu'il y a bien un utilisateur avec cet identifiant et on récupère les données dans la session.
            $query = $this->db->getQuery(true)
                ->select($this->db->quoteName(array('id', 'username', 'password')))
                ->from($this->db->quoteName('#__users'))
                ->where($this->db->quoteName('username') . ' = ' . $this->db->quote($results[0]->user_id))
                ->where($this->db->quoteName('requireReset') . ' = 0');
            $result = $this->db->setQuery($query)->loadObject();

            if ($result) {

                // On charge l'utilisateur.
                $user = User::getInstance($result->id);

                // On met à jour la session.
                $session = $this->getSession();
                $session->set('user', $user);

                // On met à jour les champs dans la table de session.
                $this->db->setQuery(
                    $this->db->getQuery(true)
                        ->update($this->db->quoteName('#__session'))
                        ->set($this->db->quoteName('guest') . ' = 0')
                        ->set($this->db->quoteName('username') . ' = ' . $this->db->quote($user->username))
                        ->set($this->db->quoteName('userid') . ' = ' . (int) $user->id)
                        ->where($this->db->quoteName('session_id') . ' = ' . $this->db->quote($session->getId()))
                );

                $this->db->execute();

                // On crée un cookie d'authentification.
                $options['user'] = $user;
                $this->createAuthenticationCookie($options);

                return true;
            }

            if (!isset($options['silent']) || !$options['silent']) {
                $this->enqueueMessage(Text::_("APP_ERROR_LOGIN_NO_USER"), "danger");
            }

            return false;

        } else { // Sinon on procède à l'authentification classique.

            // On vérifie les données.
            $this->db->setQuery(
                $this->db->getQuery(true)
                    ->select('id, password, username, block')
                    ->from('#__users')
                    ->where('username = ' . $this->db->quote($credentials['username'])
                    )
            );

            $res = $this->db->loadObject();

            // Si on a trouvé l'utilisateur.
            // C'est déjà pas mal !
            if ($res) {

                // Si l'utilisateur est bloqué, il lui est impossible de se connecter.
                if ($res->block == "1") {

                    if (!isset($options['silent']) || !$options['silent']) {
                        $this->enqueueMessage(Text::_("APP_ERROR_LOGIN_BLOCKED_USER"), "danger");
                    }

                    return false;
                }

                // On instancie la mécanique de vérification.
                $simpleAuth = new Simple();

                // On contrôle le mot de passe avec le hash dans la base de données.
                if ($simpleAuth->verify($credentials['password'], $res->password)) {

                    // C'est bon !

                    // On charge l'utilisateur.
                    $user = User::getInstance($res->id);

                    // On met à jour la session.
                    $session = $this->getSession();
                    $session->set('user', $user);

                    // On met à jour les champs dans la table de session.
                    $this->db->setQuery(
                        $this->db->getQuery(true)
                            ->update($this->db->quoteName('#__session'))
                            ->set($this->db->quoteName('guest') . ' = 0')
                            ->set($this->db->quoteName('username') . ' = ' . $this->db->quote($user->username))
                            ->set($this->db->quoteName('userid') . ' = ' . (int) $user->id)
                            ->where($this->db->quoteName('session_id') . ' = ' . $this->db->quote($session->getId()))
                    );

                    $this->db->execute();

                    // On crée un cookie d'authentification.
                    $options['user'] = $user;
                    $this->createAuthenticationCookie($options);

                    return true;
                }

            }

            if (isset($options['silent']) && !$options['silent']) {
                $this->enqueueMessage(Text::_("APP_ERROR_LOGIN_INVALID_USERNAME_OR_PASSWORD"), "danger");
            }

            return false;

        }

    }

    /**
     * Méthode pour récupérer un hash du user agent qui n'inclut pas la version du navigateur.
     * A cause du changement régulier de version.
     *
     * @return  string  Un hash du user agent avec la version remplacée par 'abcd'
     */
    public function getShortHashedUserAgent() {

        $uaString       = $this->client->userAgent;
        $browserVersion = $this->client->browserVersion;
        $uaShort        = str_replace($browserVersion, 'abcd', $uaString);

        return md5($this->get('uri.base.full') . $uaShort);
    }

    /**
     * Méthode pour créer un cookie d'authentification pour l'utilisateur.
     *
     * @param array $options Un tableau d'options.
     *
     * @return bool True en cas de succès, false sinon.
     */
    protected function createAuthenticationCookie($options) {

        // L'utilisateur a utilisé un cookie pour se connecter.
        if (isset($options['useCookie']) && $options['useCookie']) {

            $cookieName	= $this->getShortHashedUserAgent();

            // On a besoin des anciennes données pour récupérer la série existante.
            $cookieValue = $this->input->cookie->get($cookieName);
            $cookieArray = explode('.', $cookieValue);

            // On filtre la série car on va les utiliser dans la requête.
            $filter	= new InputFilter;
            $series	= $filter->clean($cookieArray[1], 'ALNUM');

        } elseif (isset($options['remember']) && $options['remember']) { // Ou il a demandé à être reconnu lors sa prochaine connexion.

            $cookieName	= $this->getShortHashedUserAgent();

            // On crée une série unique qui sera utilisée pendant la durée de vie du cookie.
            $unique = false;

            do {
                $series = User::genRandomPassword(20);
                $query = $this->db->getQuery(true)
                    ->select($this->db->quoteName('series'))
                    ->from($this->db->quoteName('#__user_keys'))
                    ->where($this->db->quoteName('series') . ' = ' . $this->db->quote($series));
                $results = $this->db->setQuery($query)->loadResult();

                if (is_null($results)) {
                    $unique = true;
                }

            } while ($unique === false);

        } else { // Sinon, on ne fait rien.

            return false;
        }

        // On récupère les valeurs de la configuration.
        $lifetime = $this->get('cookie_lifetime', '60') * 24 * 60 * 60;
        $length	  = $this->get('key_length', '16');

        // On génère un nouveau cookie.
        $token       = User::genRandomPassword($length);
        $cookieValue = $token . '.' . $series;

        // On écrase le cookie existant avec la nouvelle valeur.
        $this->input->cookie->set(
            $cookieName, $cookieValue, time() + $lifetime, $this->get('cookie_path', '/'), $this->get('cookie_domain'), $this->isSSLConnection()
        );
        $query = $this->db->getQuery(true);

        if (isset($options['remember']) && $options['remember']) {

            // On crée un nouvel enregistrement.
            $query
                ->insert($this->db->quoteName('#__user_keys'))
                ->set($this->db->quoteName('user_id') . ' = ' . $this->db->quote($options['user']->username))
                ->set($this->db->quoteName('series') . ' = ' . $this->db->quote($series))
                ->set($this->db->quoteName('uastring') . ' = ' . $this->db->quote($cookieName))
                ->set($this->db->quoteName('time') . ' = ' . (time() + $lifetime));
        } else {
            // On met à jour l'enregistrement existant avec le nouveau jeton.
            $query
                ->update($this->db->quoteName('#__user_keys'))
                ->where($this->db->quoteName('user_id') . ' = ' . $this->db->quote($options['user']->username))
                ->where($this->db->quoteName('series') . ' = ' . $this->db->quote($series))
                ->where($this->db->quoteName('uastring') . ' = ' . $this->db->quote($cookieName));
        }

        $simpleAuth   = new Simple();
        $hashed_token = $simpleAuth->create($token);
        $query->set($this->db->quoteName('token') . ' = ' . $this->db->quote($hashed_token));
        $this->db->setQuery($query)->execute();

        return true;
    }

    /**
     * Initialise l'application.
     *
     * C'est ici qu'on instancie le routeur de l'application les routes correspondantes vers les controllers.
     */
    protected function initialise() {

        // On instancie le logger si besoin.
        if ($this->get('log', false)) {

            $logger = new Logger($this->get('sitename'));

            if (is_dir(JPATH_LOGS)) {
                $logger->pushHandler(new StreamHandler(JPATH_LOGS."/". $this->get('log_file'), (JDEBUG ? Logger::DEBUG : Logger::WARNING)));
            } else { // If the log path is not set, just use a null logger.
                $logger->pushHandler(new NullHandler, (JDEBUG ? Logger::DEBUG : Logger::WARNING));
            }

            $this->setLogger($logger);

        }

        // On instancie la session.
        $this->setSession(Session::getInstance('Database', array(
            'db' => $this->getDb()
        )));

        // On initialise la session.
        $session = $this->getSession();
        $session->initialise($this->input);
        $session->start();

        // On initialise l'état utilisateur.
        if ($session->isNew()) {
            $session->set('state', new Registry);
        }

        // On crée la session dans la base de données.
        $this->createDbSession();

        // On personnalise l'environnement suivant l'utilisateur dans la session.
        $user = $session->get('user');
        if ($user) {

            $language = $user->params->get('language');

            // On s'assure que la langue de l'utilisateur existe.
            if ($language && Language::exists($language)) {
                $this->set('language', $language);
            }

            $timezone = $user->params->get('timezone');
            if ($timezone) {
                $this->set('timezone', $timezone);
            }

        }

        // On instancie le routeur.
        $this->router = new Router($this->input);
        $this->router->setControllerPrefix($this->get('controller_prefix'));
        $this->router->setDefaultController($this->get('default_controller'));

        // On définit les routes.
        $this->router->addMaps($this->get('routes', array()));

        // On initialise la langue.
        $this->getLanguage();

        // On définit le fuseau horaire.
        @date_default_timezone_set($this->get('timezone', 'Europe/Paris'));

    }

    /**
     * Effectue la logique de l'application.
     */
    protected function doExecute() {

        // On tente d'auto-connecter l'utilisateur.
        $this->loginWithCookie();

        // On récupère le controller.
        $controller = $this->route();

        // On sauvegarde le controller actif.
        $this->_activeController = strtolower($controller->getName());

        try {

            // On exécute la logique du controller et on récupère le résultat.
            $result = $controller->execute();

            // On effectue le rendu de la page avec le résultat.
            $this->render($result);

        } catch (\Exception $e) {
            $this->raiseError($e->getMessage(), $e->getCode(), $e);
        }

    }

    /**
     * Route l'application.
     *
     * Le routage est le processus pendant lequel on examine la requête pour déterminer
     * quel controller doit recevoir la requête.
     *
     * @param  string $route La route a analyser. (Optionnel, REQUEST_URI par défaut)
     *
     * @return \EtdSolutions\Framework\Controller\Controller Le controller
     */
    protected function route($route = null) {

        if (!isset($route)) {
            $route = $_SERVER['REQUEST_URI'];
        }

        try {
            // On détermine le controller grâce au router.
            $controller = $this->router->getController($route);
        } catch (\Exception $e) {
            $this->raiseError($e->getMessage(), $e->getCode(), $e);
        }

        return $controller;

    }

    /**
     * Effectue le rendu de l'application.
     *
     * Le rendu est le résultat du traitement du résultat du contrôleur.
     * Si c'est une chaine de caractère on assume que c'est de l'HTML et donc on renvoie
     * du text/html. Dans le cas contraire, on transforme le résultat en chaine de
     * caractère au format JSON.
     *
     * On modifie aussi ici les headers de la réponse pour l'adapter au résultat.
     *
     */
    protected function render($result) {

        // C'est un string => HTML
        if (is_string($result)) {

            // On modifie le type MIME de la réponse.
            $this->mimeType = 'text/html';

            // On récupère le document.
            $doc = $this->getDocument();

            // On parse le document
            $doc->parse();

            // Description
            $doc->setDescription($this->get('description'));

            // Contenu du controller
            $doc->setPositionContent('main', $result);

            // On effectue le rendu du document.
            $data = $doc->render();

        } elseif (is_object($result)) { // C'est un objet => JSON

            // On modifie le type MIME de la réponse.
            $this->mimeType = 'application/json';

            // Si l'on a un code de statut HTTP.
            if (property_exists($result, 'status')) {
                switch ($result->status) {
                    case 400:
                        $status = '400 Bad Request';
                        break;
                    case 401:
                        $status = '401 Unauthorized';
                        break;
                    case 403:
                        $status = '403 Forbidden';
                        break;
                    case 404:
                        $status = '404 Not found';
                        break;
                    case 500:
                        $status = '500 Internal Server Error';
                        break;
                    default:
                        $status = '200 OK';
                        break;
                }
                $this->setHeader('status', $status);
                unset($result->status);
            }

            $data = json_encode($result);

        } else {
            $this->raiseError(Text::_('APP_ERROR_INVALID_RESULT'));
        }

        // On affecte le résultat au corps de la réponse.
        $this->setBody($data);

    }

    /**
     * Méthode pour envoyer la réponse de l'application au client.
     * Toutes les entêtes seront envoyées avant le contenu principal
     * des données de sortie de l'application.
     *
     * @return  void
     */
    protected function respond() {
        parent::respond();

        // On oublie pas de fermer la porte en partant !
        $this->close();
    }

    /**
     * Méthode pour contrôler la sesion de l'utilisateur.
     *
     * Si l'enregistrement de la session n'existe pas, on l'initialise.
     * Si la session est nouvelle, on créer les variables de session.
     *
     * @return  void
     */
    protected function createDbSession() {

        $db      = $this->db;
        $session = $this->getSession();

        try {

            $query = $db->getQuery(true)
                        ->select($db->quoteName('session_id'))
                        ->from($db->quoteName('#__session'))
                        ->where($db->quoteName('session_id') . ' = ' . $db->quote($session->getId()));

            $db->setQuery($query, 0, 1);
            $exists = $db->loadResult();

            // Si la session n'existe pas, on l'initialise.
            if (!$exists) {
                $query->clear();
                if ($session->isNew()) {
                    $query->insert($db->quoteName('#__session'))
                          ->columns($db->quoteName('session_id') . ', ' . $db->quoteName('time'))
                          ->values($db->quote($session->getId()) . ', ' . $db->quote((int)time()));
                    $db->setQuery($query);
                } else {
                    $query->insert($db->quoteName('#__session'))
                          ->columns($db->quoteName('session_id') . ', ' . $db->quoteName('time'))
                          ->values($db->quote($session->getId()) . ', ' . $db->quote((int)$session->get('session.timer.start')));
                    $db->setQuery($query);

                    $db->setQuery($query);
                }

                // Si l'insertion a échoué, on quitte l'application.
                $db->execute();
            }

        } catch (\RuntimeException $e) {
            exit($e->getMessage());
        }
    }

    /**
     * Méthode pour tenter d'auto-connecter l'utilisateur (non connecté bien sûr) grâce au cookie.
     */
    protected function loginWithCookie() {

        // On procède à l'authentification de l'utilisateur par cookie s'il n'est pas déjà connecté.
        $user = $this->getSession()->get('user');
        if (!$user || ($user && $user->isGuest())) {

            $cookieName = $this->getShortHashedUserAgent();

            // On contrôle que le cookie existe.
            if ($this->input->cookie->get($cookieName)) {

                // On effectue une authentification silencieuse.
                $this->login(array('username' => ''), array('useCookie' => true));//, 'silent' => true));

            }

        }

    }

}