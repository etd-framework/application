<?php
/**
 * Part of the ETD Framework Application Package
 *
 * @copyright   Copyright (C) 2015 ETD Solutions, SARL Etudoo. Tous droits réservés.
 * @license     Apache License 2.0; see LICENSE
 * @author      ETD Solutions http://etd-solutions.com
 */

namespace EtdSolutions\Application;

use EtdSolutions\Acl\Acl;
use EtdSolutions\Controller\Controller;
use EtdSolutions\Language\LanguageFactory;
use EtdSolutions\Model\Model;
use EtdSolutions\User\User;
use EtdSolutions\View\HtmlView;

use Joomla\Application\AbstractWebApplication;
use Joomla\Crypt\Password\Simple;
use Joomla\DI\ContainerAwareInterface;
use Joomla\DI\ContainerAwareTrait;
use Joomla\Filter\InputFilter;
use Joomla\Language\LanguageHelper;
use Joomla\Registry\Registry;
use Joomla\Router\Router;
use Joomla\Uri\Uri;

use Monolog\Handler\NullHandler;
use Monolog\Handler\StreamHandler;
use Monolog\Logger;

class Web extends AbstractWebApplication implements ContainerAwareInterface {

    use ContainerAwareTrait;

    /**
     * @var Router  Le router de l'application.
     */
    public $router;

    /**
     * @var array Liste des messages devant être affichés à l'utilisateur.
     */
    protected $_messageQueue = array();

    /**
     * @var array Dernière erreur.
     */
    protected $error;

    /**
     * @var string Nom du controller actif dans l'application.
     */
    protected $_activeController = '';

    /**
     * Redirige le navigateur vers une nouvelle adresse.
     *
     * @param string $url     La nouvelle URL
     * @param string $msg     Message a afficher à l'utilisateur
     * @param string $msgType Type du message
     * @param bool   $moved   Redirection 301 pour indiquer une page qui a changé d'emplacement (SEF)
     */
    public function redirect($url, $msg = '', $msgType = 'message', $moved = false) {

        // If the message exists, enqueue it.
        if (trim($msg)) {
            $this->enqueueMessage($msg, $msgType);
        }

        // Persist messages if they exist.
        if (count($this->_messageQueue)) {
            $session = $this->getSession();
            $session->set('application.queue', $this->_messageQueue);
        }

        parent::redirect($url, $moved);
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

        $session      = $this->getSession();
        $sessionQueue = $session->get('application.queue');

        if (count($sessionQueue)) {
            $this->_messageQueue = array_merge($sessionQueue, $this->_messageQueue);
            $session->set('application.queue', null);
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

        if ($this->get('debug', 0)) {
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

        // On définit les entêtes HTTP.
        $this->setHeader('status', $status);

        // On sauve l'erreur dans l'appli.
        $this->setError($message, $code, $exception);
        $this->_activeController = 'error';

        // On a besoin du controller par défaut pour récupérer le renderer.
        $controller = (new Controller($this->input, $this))->setContainer($this->getContainer());

        // On construit un objet View par défaut et on effectue le rendu avec le layout "error".
        $controller->initializeRenderer();
        $view = new HtmlView(new Model($this, $this->getContainer()->get('db')), $this->getContainer()->get('renderer'));
        $view->setContainer($this->getContainer());

        $this->setBody($view->setLayout('error')->setData([
            'message'   => $message,
            'code'      => $code,
            'exception' => $exception
        ])->render());

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
     * @param   array $credentials Array('username' => string, 'password' => string)
     * @param   array $options     Array('remember' => boolean)
     *
     * @return  boolean  True en cas de succès.
     */
    public function login($credentials, $options = array()) {

        /**
         * @var $db \Joomla\Database\DatabaseDriver
         */
        $db = $this->getContainer()->get('db');

        $factory = new LanguageFactory;
        $text = $factory->getText();

        // Si on a demandé l'authentification par cookie.
        if (isset($options['useCookie']) && $options['useCookie']) {

            // On récupère le cookie.
            $cookieName  = $this->getShortHashedUserAgent();
            $cookieValue = $this->input->cookie->get($cookieName);

            if (!$cookieValue) {

                if (!isset($options['silent']) || !$options['silent']) {
                    $this->enqueueMessage($text->translate("APP_ERROR_LOGIN_INVALID_COOKIE"), "danger");
                }

                return false;
            }

            $cookieArray = explode('.', $cookieValue);

            // On contrôle que le cookie est valide.
            if (count($cookieArray) != 2) {

                // On détruit le cookie dans le navigateur.
                $this->input->cookie->set($cookieName, false, time() - 42000, $this->get('cookie_path', '/'), $this->get('cookie_domain'));

                if (!isset($options['silent']) || !$options['silent']) {
                    $this->enqueueMessage($text->translate("APP_ERROR_LOGIN_INVALID_COOKIE"), "danger");
                }

                return false;
            }

            // On filtre les entrées car on va les utiliser dans la requête.
            $filter = new InputFilter;
            $series = $filter->clean($cookieArray[1], 'ALNUM');

            // On retire les jetons expirés.
            $query = $db->getQuery(true)
                              ->delete('#__user_keys')
                              ->where($db->quoteName('time') . ' < ' . $db->quote(time()));
            $db->setQuery($query)
                     ->execute();

            // On trouve un enregistrement correspondant s'il existe.
            $query   = $db->getQuery(true)
                                ->select($db->quoteName(array(
                                    'user_id',
                                    'token',
                                    'series',
                                    'time'
                                )))
                                ->from($db->quoteName('#__user_keys'))
                                ->where($db->quoteName('series') . ' = ' . $db->quote($series))
                                ->where($db->quoteName('uastring') . ' = ' . $db->quote($cookieName))
                                ->order($db->quoteName('time') . ' DESC');
            $results = $db->setQuery($query)
                                ->loadObjectList();

            if (count($results) !== 1) {

                // On détruit le cookie dans le navigateur.
                $this->input->cookie->set($cookieName, false, time() - 42000, $this->get('cookie_path', '/'), $this->get('cookie_domain'));

                if (!isset($options['silent']) || !$options['silent']) {
                    $this->enqueueMessage($text->translate("APP_ERROR_LOGIN_INVALID_COOKIE"), "danger");
                }

                return false;
            } else { // On a un utilisateur avec un cookie valide qui correspond à un enregistrement en base.

                // On instancie la mécanique de vérification.
                $simpleAuth = new Simple();

                //$token = $simpleAuth->create($cookieArray[0]);

                if (!$simpleAuth->verify($cookieArray[0], $results[0]->token)) {

                    // C'est une attaque réelle ! Soit on a réussi à créer un cookie valide ou alors on a volé le cookie et utilisé deux fois (une fois par le pirate et une fois par la victime).
                    // On supprime tous les jetons pour cet utilisateur !
                    $query = $db->getQuery(true)
                                      ->delete('#__user_keys')
                                      ->where($db->quoteName('user_id') . ' = ' . $db->quote($results[0]->user_id));
                    $db->setQuery($query)
                             ->execute();

                    // On détruit le cookie dans le navigateur.
                    $this->input->cookie->set($cookieName, false, time() - 42000, $this->get('cookie_path', '/'), $this->get('cookie_domain'));

                    //@TODO: logguer l'attaque et envoyer un mail à l'admin.

                    if (!isset($options['silent']) || !$options['silent']) {
                        $this->enqueueMessage($text->translate("APP_ERROR_LOGIN_INVALID_COOKIE"), "danger");
                    }

                    return false;
                }
            }

            // On s'assure qu'il y a bien un utilisateur avec cet identifiant et on récupère les données dans la session.
            $query  = $db->getQuery(true)
                               ->select($db->quoteName(array(
                                   'id',
                                   'username',
                                   'password'
                               )))
                               ->from($db->quoteName('#__users'))
                               ->where($db->quoteName('username') . ' = ' . $db->quote($results[0]->user_id))
                               ->where($db->quoteName('requireReset') . ' = 0');
            $result = $db->setQuery($query)
                               ->loadObject();

            if ($result) {

                // On charge l'utilisateur.
                $user = $this->getContainer()->get('user')->load($result->id);

                // On effectue les dernières vérifications.
                if (!$this->authoriseLogin($user)) {
                    if (!isset($options['silent']) || !$options['silent']) {
                        $this->enqueueMessage($text->translate("APP_ERROR_LOGIN_BLOCKED_USER"), "danger");
                    }

                    return false;
                }

                // On met à jour la dernière visite.
                $user->setLastVisit();

                // On met à jour la session.
                $session = $this->getSession();
                $session->set('user_id', $user->id);
                $session->set('from_cookie', true);

                // On met à jour les champs dans la table de session.
                $db->setQuery($db->getQuery(true)
                                             ->update($db->quoteName('#__session'))
                                             ->set($db->quoteName('guest') . ' = 0')
                                             ->set($db->quoteName('username') . ' = ' . $db->quote($user->username))
                                             ->set($db->quoteName('userid') . ' = ' . (int)$user->id)
                                             ->where($db->quoteName('session_id') . ' = ' . $db->quote($session->getId())));

                $db->execute();

                // On crée un cookie d'authentification.
                $options['user'] = $user;
                $this->createAuthenticationCookie($options);

                return true;
            }

            if (!isset($options['silent']) || !$options['silent']) {
                $this->enqueueMessage($text->translate("APP_ERROR_LOGIN_NO_USER"), "danger");
            }

            return false;

        } else { // Sinon on procède à l'authentification classique.

            // On vérifie les données.
            $db->setQuery($db->getQuery(true)
                                         ->select('id, password, username, block')
                                         ->from('#__users')
                                         ->where('username = ' . $db->quote($credentials['username'])));

            $res = $db->loadObject();

            // Si on a trouvé l'utilisateur.
            // C'est déjà pas mal !
            if ($res) {

                // Si l'utilisateur est bloqué, il lui est impossible de se connecter.
                if ($res->block == "1") {

                    if (!isset($options['silent']) || !$options['silent']) {
                        $this->enqueueMessage($text->translate("APP_ERROR_LOGIN_BLOCKED_USER"), "danger");
                    }

                    return false;
                }

                // On instancie la mécanique de vérification.
                $simpleAuth = new Simple();

                // On contrôle le mot de passe avec le hash dans la base de données.
                if ($simpleAuth->verify($credentials['password'], $res->password)) {

                    // C'est presque bon !

                    // On charge l'utilisateur.
                    $user = $this->getContainer()->get('user')->load($res->id);

                    // On effectue les dernières vérifications.
                    if (!$this->authoriseLogin($user)) {
                        if (!isset($options['silent']) || !$options['silent']) {
                            $this->enqueueMessage($text->translate("APP_ERROR_LOGIN_BLOCKED_USER"), "danger");
                        }

                        return false;
                    }

                    // On met à jour la dernière visite.
                    $user->setLastVisit();

                    // On met à jour la session.
                    $session = $this->getSession();
                    $session->set('user_id', $user->id);
                    $session->set('from_cookie', false);

                    // On met à jour les champs dans la table de session.
                    $db->setQuery($db->getQuery(true)
                                                 ->update($db->quoteName('#__session'))
                                                 ->set($db->quoteName('guest') . ' = 0')
                                                 ->set($db->quoteName('username') . ' = ' . $db->quote($user->username))
                                                 ->set($db->quoteName('userid') . ' = ' . (int)$user->id)
                                                 ->where($db->quoteName('session_id') . ' = ' . $db->quote($session->getId())));

                    $db->execute();

                    // On crée un cookie d'authentification.
                    $options['user'] = $user;
                    $this->createAuthenticationCookie($options);

                    return true;
                }

            }

            if (isset($options['silent']) && !$options['silent']) {
                $this->enqueueMessage($text->translate("APP_ERROR_LOGIN_INVALID_USERNAME_OR_PASSWORD"), "danger");
            }

            return false;

        }

    }

    /**
     * Méthode pour autoriser la connexion de l'utilisateur en
     * dernier lieu (après vérification du mot de passe).
     *
     * Par défaut c'est ok. A implémenter dans les applis.
     *
     * @param User $user
     *
     * @return bool
     */
    protected function authoriseLogin($user) {

        return true;

    }

    /**
     * Méthode pour déconnecter l'utilisateur.
     *
     * @return bool True si succès.
     */
    public function logout() {

        $container = $this->getContainer();
        $my        = $container->get('user')->load();
        $session   = $container->get('session');
        $db        = $container->get('db');

        $my->setLastVisit();

        // On supprime la session PHP.
        $session->destroy();

        // On force la déconnexion de tous les utilisateurs avec cet id.
        $db->setQuery($db->getQuery(true)
            ->delete($db->quoteName('#__session'))
            ->where($db->quoteName('userid') . ' = ' . (int)$my->id))
            ->execute();

        // On supprime tous les cookie d'authentification de l'utilisateur.
        $cookieName  = $this->getShortHashedUserAgent();
        $cookieValue = $this->input->cookie->get($cookieName);

        // S'il n y a de cookie à supprimer.
        if (!$cookieValue) {
            return true;
        }

        $cookieArray = explode('.', $cookieValue);

        // On filtre la série car on l'utilise dans la requête.
        $filter = new InputFilter;
        $series = $filter->clean($cookieArray[1], 'ALNUM');

        // On supprime l'enregistrement dans la base de données.
        $query = $db->getQuery(true);
        $query->delete('#__user_keys')
            ->where($db->quoteName('series') . ' = ' . $db->quote($series));
        $db->setQuery($query)
            ->execute();

        // On supprime le cookie.
        $this->input->cookie->set($cookieName, false, time() - 42000, $this->get('cookie.path', '/'), $this->get('cookie.domain'));

        return true;

    }

    /**
     * Checks for a form token in the request.
     *
     * Use in conjunction with getFormToken.
     *
     * @param   string  $method  The request method in which to look for the token key.
     *
     * @return  boolean  True if found and valid, false otherwise.
     *
     * @since   1.0
     */
    public function checkToken($method = 'post') {
        $token = $this->getFormToken();

        if (!$this->input->$method->get($token, '', 'alnum')) {
            if ($this->getSession()->isNew()) {
                // Redirect to login screen.
                $this->redirect('/login');
                $this->close();
            }

            return false;
        }

        return true;
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

        /**
         * @var $db \Joomla\Database\DatabaseDriver
         */
        $db = $this->getContainer()->get('db');

        // L'utilisateur a utilisé un cookie pour se connecter.
        if (isset($options['useCookie']) && $options['useCookie']) {

            $cookieName = $this->getShortHashedUserAgent();

            // On a besoin des anciennes données pour récupérer la série existante.
            $cookieValue = $this->input->cookie->get($cookieName);
            $cookieArray = explode('.', $cookieValue);

            // On filtre la série car on va les utiliser dans la requête.
            $filter = new InputFilter;
            $series = $filter->clean($cookieArray[1], 'ALNUM');

        } elseif (isset($options['remember']) && $options['remember']) { // Ou il a demandé à être reconnu lors sa prochaine connexion.

            $cookieName = $this->getShortHashedUserAgent();

            // On crée une série unique qui sera utilisée pendant la durée de vie du cookie.
            $unique = false;

            do {
                $series  = User::genRandomPassword(20);
                $query   = $db->getQuery(true)
                                    ->select($db->quoteName('series'))
                                    ->from($db->quoteName('#__user_keys'))
                                    ->where($db->quoteName('series') . ' = ' . $db->quote($series));
                $results = $db->setQuery($query)
                                    ->loadResult();

                if (is_null($results)) {
                    $unique = true;
                }

            } while ($unique === false);

        } else { // Sinon, on ne fait rien.

            return false;
        }

        // On récupère les valeurs de la configuration.
        $lifetime = $this->get('cookie.lifetime', '60') * 24 * 60 * 60;
        $length   = $this->get('cookie.key_length', '16');

        // On génère un nouveau cookie.
        $token       = User::genRandomPassword($length);
        $cookieValue = $token . '.' . $series;

        // On écrase le cookie existant avec la nouvelle valeur.
        $this->input->cookie->set($cookieName, $cookieValue, time() + $lifetime, $this->get('cookie.path', '/'), $this->get('cookie.domain'), $this->isSSLConnection());
        $query = $db->getQuery(true);

        if (isset($options['remember']) && $options['remember']) {

            // On crée un nouvel enregistrement.
            $query->insert($db->quoteName('#__user_keys'))
                  ->set($db->quoteName('user_id') . ' = ' . $db->quote($options['user']->username))
                  ->set($db->quoteName('series') . ' = ' . $db->quote($series))
                  ->set($db->quoteName('uastring') . ' = ' . $db->quote($cookieName))
                  ->set($db->quoteName('time') . ' = ' . (time() + $lifetime));
        } else {
            // On met à jour l'enregistrement existant avec le nouveau jeton.
            $query->update($db->quoteName('#__user_keys'))
                  ->where($db->quoteName('user_id') . ' = ' . $db->quote($options['user']->username))
                  ->where($db->quoteName('series') . ' = ' . $db->quote($series))
                  ->where($db->quoteName('uastring') . ' = ' . $db->quote($cookieName));
        }

        $simpleAuth   = new Simple();
        $hashed_token = $simpleAuth->create($token);
        $query->set($db->quoteName('token') . ' = ' . $db->quote($hashed_token));
        $db->setQuery($query)
                 ->execute();

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
                $logger->pushHandler(new StreamHandler(JPATH_LOGS . "/" . $this->get('log_file'), ($this->get('debug') ? Logger::DEBUG : Logger::WARNING)));
            } else { // If the log path is not set, just use a null logger.
                $logger->pushHandler(new NullHandler, ($this->get('debug') ? Logger::DEBUG : Logger::WARNING));
            }

            $this->setLogger($logger);

        }

    }

    protected function loadSystemUris($requestUri = null) {

        parent::loadSystemUris($requestUri);

        $uri = new Uri($this->get('uri.request'));
        $this->set('uri.current', $uri->toString(['scheme', 'user', 'pass', 'host', 'port', 'path']));

    }

    /**
     * Effectue la logique de l'application.
     */
    protected function doExecute() {

        // Config
        $this->getContainer()->get('config')->merge($this->config);
        $this->setConfiguration($this->getContainer()->get('config'));

        // On récupère la session.
        $session = $this->getContainer()->get('session');
        $this->setSession($session);

        // On nettoie les veilles sessions
        $this->sessionCleanUp();

        // On démarre la session.
        $session->start();

        // Si c'est une requête pour garder en vie la session, on peut quitter ici.
        if ($this->input->get('stayAlive', false, 'bool') === true) {
            echo "1";
            $this->close();
        }

        // On initialise l'état utilisateur.
        if ($session->isNew() || $session->get('state') === null) {
            $session->set('state', new Registry);
        }

        // On tente d'auto-connecter l'utilisateur.
        $this->loginWithCookie();

        // On personnalise l'environnement suivant l'utilisateur dans la session.
        $user = $session->get('user');
        if ($user) {

            $language = $user->params->get('language');
            $helper   = new LanguageHelper;

            // On s'assure que la langue de l'utilisateur existe.
            if ($language && $helper->exists($language, JPATH_ROOT)) {
                $this->set('language', $language);
            }

            $timezone = $user->params->get('timezone');
            if ($timezone) {
                $this->set('timezone', $timezone);
            }

        }

        // On définit le fuseau horaire.
        @date_default_timezone_set($this->get('timezone', 'Europe/Paris'));

        // On récupère le controller.
        $controller = $this->route();

        // On contrôle si l'utilisateur doit changer son mot de passe.
        $this->checkUserRequireReset($controller);

        // On redirige en HTTPS si besoin.
        /*if ($this->get('force_ssl') && !$this->isSSLConnection() && $controller->isSSLEnabled()) {
            $uri = new Uri($this->get('uri.request'));
            $uri->setScheme('https');
            $this->redirect((string)$uri);
        }*/

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
     * @return Controller Le controller
     */
    protected function route($route = null) {

        if (!isset($route)) {
            $route = $_SERVER['REQUEST_URI'];
        }

        try {

            // On instancie le routeur.
            $router = new Router($this->input);
            $router->setControllerPrefix($this->get('controller_prefix'));
            $router->setDefaultController($this->get('default_controller'));

            // On définit les routes.
            $router->addMaps($this->get('routes', array()));

            // On détermine le controller grâce au router.
            $controller = $router->getController($route);
            $controller->setApplication($this);

            // Si le controller est ContainerAware, on lui injecte le container DI.
            if ($controller instanceof ContainerAwareInterface) {
                $controller->setContainer($this->getContainer());
            }

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

            $data = $result;

        } elseif (is_object($result) || is_array($result)) { // C'est un objet => JSON

            $r = (object) $result;

            // On modifie le type MIME de la réponse.
            $this->mimeType = 'application/json';

            // Si l'on a un code de statut HTTP.
            if (property_exists($r, 'status')) {
                switch ($r->status) {
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

                if (is_object($result)) {
                    unset($result->status);
                } else {
                    unset($result['status']);
                }

            }

            $data = json_encode($result);

        } else {
            $text = (new LanguageFactory())->getText();
            $this->raiseError($text->translate('APP_ERROR_INVALID_RESULT'));
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
     * Méthode pour tenter d'auto-connecter l'utilisateur (non connecté bien sûr) grâce au cookie.
     */
    protected function loginWithCookie() {

        $session_id = $this->getSession()->getId();
        $container  = $this->getContainer();
        $db         = $container->get('db');

        // On récupère l'état associé à la session.
        $isGuest = $db->setQuery("SELECT guest FROM #__session WHERE session_id = " . $db->quote($session_id))->loadResult();

        // On connecte l'utilisateur par cookie, seulement s'il invité.
        if (!isset($isGuest) || $isGuest == "1") {

            $cookieName = $this->getShortHashedUserAgent();

            // On contrôle que le cookie existe.
            if ($this->input->cookie->get($cookieName)) {

                // On effectue une authentification silencieuse.
                $this->login(array('username' => ''), array('useCookie' => true, 'silent' => true));

            }

        }

    }

    /**
     * Méthode pour contrôler que l'utilisateur doit ou ne doit pas changer son mot de passe.
     *
     * Si l'utilisateur doit changer son mot de passe, on le redirige vers la page qui gère ça.
     *
     * @return  void
     */
    protected function checkUserRequireReset($controller) {

        $user = $this->getContainer()->get('user')->load();

        if ($user->requireReset) {

            /*
             * Par défaut, c'est la page d'édition du profil qui est utilisée.
             * Cette page permet de changer plus que le mot de passe et peut ne pas être le comportement désiré.
             * On peut surcharger la page qui gère la remise à zero en changeant la configuration.
             */
            $classname = $this->get('controller_prefix') . $this->get('reset_password.controller');

            if ($classname !== null && !($controller instanceof $classname)) {

                $text = $this->getContainer()->get('language')->getText();

                // On redirige vers la page.
                $this->enqueueMessage($text->translate('APP_GLOBAL_PASSWORD_RESET_REQUIRED'), 'notice');
                $this->redirect("/".$this->get('reset_password.uri'));

            }

        }
    }

    protected function sessionCleanUp() {

        $storage = $this->getContainer()->get('storage');
        if ($storage instanceof \Joomla\Session\StorageInterface) {
            $handler = $this->getContainer()->get('storage')->getHandler();
            $handler->gc($this->get('session_expire') * 2);
            $handler->close();
            $handler->open(null,null);
        }

        return $this;

    }

}