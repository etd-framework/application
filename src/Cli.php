<?php
/**
 * Part of the ETD Framework Application Package
 *
 * @copyright   Copyright (C) 2015 ETD Solutions, SARL Etudoo. Tous droits réservés.
 * @license     Apache License 2.0; see LICENSE
 * @author      ETD Solutions http://etd-solutions.com
 */

namespace EtdSolutions\Application;

use Joomla\Application\AbstractCliApplication;
use Joomla\Application\Cli\CliInput;
use Joomla\Application\Cli\CliOutput;
use Joomla\DI\Container;
use Joomla\DI\ContainerAwareInterface;
use Joomla\DI\ContainerAwareTrait;

abstract class Cli extends AbstractCliApplication implements ContainerAwareInterface {

    use ContainerAwareTrait;

    public function __construct(Container $container, Cli $input = null, CliOutput $output = null, CliInput $cliInput = null) {

        $this->setContainer($container);

        parent::__construct($input, $container->get('config'), $output, $cliInput);
    }

}