<?php
/**
 * Part of the ETD Framework Application Package
 *
 * @copyright   Copyright (C) 2015 ETD Solutions, SARL Etudoo. Tous droits réservés.
 * @license     Apache License 2.0; see LICENSE
 * @author      ETD Solutions http://etd-solutions.com
 */

namespace EtdSolutions\Application;

use EtdSolutions\Router\RestRouter;

use Joomla\Application\AbstractWebApplication;
use Joomla\Application\Web;
use Joomla\DI\ContainerAwareInterface;
use Joomla\DI\ContainerAwareTrait;
use Joomla\Uri\Uri;

use Monolog\Handler\NullHandler;
use Monolog\Handler\StreamHandler;
use Monolog\Logger;

class Rest extends AbstractWebApplication implements ContainerAwareInterface {

    use ContainerAwareTrait;

    /**
     * @var string Le controller actif.
     */
    protected $activeController;

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

        if ($this->get('json_options') === null) {
            $this->set('json_options', JSON_PRETTY_PRINT + JSON_UNESCAPED_SLASHES);
        }

    }

    /**
     * Execute the application.
     *
     * @return  void
     */
    public function execute() {

        $container = $this->getContainer();
        $profiler  = $container->has('profiler') ? $container->get('profiler') : false;

        if ($this->get('debug') && $profiler) {
            $this->set('gzip', false);
            ob_start();
            ob_implicit_flush(false);
        }

        if ($profiler) {
            $profiler->mark('beforeExecute');
        }

        // Perform application routines.
        $this->doExecute();

        if ($profiler) {
            $profiler->mark('afterExecute');
        }

        // If gzip compression is enabled in configuration and the server is compliant, compress the output.
        if ($this->get('gzip') && !ini_get('zlib.output_compression') && (ini_get('output_handler') != 'ob_gzhandler')) {
            $this->compress();
        }

        if ($profiler) {
            $profiler->mark('beforeRespond');
        }

        // Send the application response.
        $this->respond();

        if ($profiler) {
            $profiler->mark('afterRespond');
            $profiler->mark('end');
            $profiler->dump($this->get('uri.current'));
        }
    }

    protected function doExecute() {

        $container = $this->getContainer();

        // On affecte le logger si besoin.
        if ($container->has('logger')) {
            $this->setLogger($container->get('logger'));
        }

        // On redirige en HTTPS si besoin.
        if ($this->get('force_ssl') && !$this->isSSLConnection()) {
            $uri = new Uri($this->get('uri.request'));
            $uri->setScheme('https');
            $this->redirect((string)$uri);
        }

        // Config
        $container->get('config')
                  ->merge($this->config);
        $this->setConfiguration($container->get('config'));

        // On définit le fuseau horaire.
        @date_default_timezone_set($this->get('timezone', 'Europe/Paris'));

        // On récupère le controller.
        $controller = $this->route();

        // On sauvegarde le controller actif.
        $this->activeController = strtolower($controller->getName());

        $profiler = $this->container->has('profiler') ? $this->container->get('profiler') : false;

        if ($profiler) {
            $profiler->mark('beforeControllerExecute');
        }

        // On exécute la logique du controller et on récupère le résultat.
        $result = $controller->execute();

        if ($profiler) {
            $profiler->mark('afterControllerExecute');
        }

        // On effectue le rendu de la page avec le résultat.
        $this->render($result);

    }

    /**
     * Route l'application.
     *
     * Le routage est le processus pendant lequel on examine la requête pour déterminer
     * quel controller doit recevoir la requête.
     *
     * @param  string $route La route a analyser. (Optionnel, REQUEST_URI par défaut)
     *
     * @return \EtdSolutions\Controller\Controller Le controller
     */
    protected function route($route = null) {

        $profiler = $this->container->has('profiler') ? $this->container->get('profiler') : false;

        if ($profiler) {
            $profiler->mark('beforeRoute');
        }

        if (!isset($route)) {
            $route = $_SERVER['REQUEST_URI'];
        }

        try {

            // On instancie le routeur.
            $router = new RestRouter($this->input);
            $router->setControllerPrefix($this->get('controller_prefix'));
            $router->setDefaultController($this->get('default_controller'));

            // On définit les routes.
            $compiled_routes = $this->get('compiled_routes');
            if (isset($compiled_routes)) {
                $router->setMaps($this->get('compiled_routes', array()));
            } else {
                $router->addMaps($this->get('routes', array()));
            }

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

        if ($profiler) {
            $profiler->mark('afterRoute');
        }

        return $controller;

    }

    protected function render($result) {

        $profiler = $this->container->has('profiler') ? $this->container->get('profiler') : false;

        if ($profiler) {
            $profiler->mark('beforeRender');
        }

        $r = (object)$result;

        // On modifie le type MIME de la réponse.
        $this->mimeType = 'application/json';

        // Pas de cache
        $this->allowCache(false);

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

        $data = json_encode($result, $this->get('json_options'));

        // On affecte le résultat au corps de la réponse.
        $this->setBody($data);

        if ($profiler) {
            $profiler->mark('afterRender');
        }

    }

    /**
     * @param string     $message
     * @param int        $code
     * @param \Exception $exception
     */
    public function raiseError($message, $code, $exception = null) {

        $ret = [
            "error"   => true,
            "message" => $message,
            "code"    => $code,
            "status"  => $code
        ];

        if (isset($exception) && $this->getContainer()
                                      ->get('config')
                                      ->get('debug')
        ) {
            $ret["backtrace"] = $exception->getTrace();
            $ret["exception"] = $exception;
        }

        $this->render($ret);

        // If gzip compression is enabled in configuration and the server is compliant, compress the output.
        if ($this->get('gzip') && !ini_get('zlib.output_compression') && (ini_get('output_handler') != 'ob_gzhandler')) {
            $this->compress();
        }

        $this->respond();

        exit;

    }

}