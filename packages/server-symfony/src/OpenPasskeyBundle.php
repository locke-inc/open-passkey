<?php

declare(strict_types=1);

namespace OpenPasskey\Symfony;

use OpenPasskey\Server\CredentialStore;
use OpenPasskey\Server\PasskeyConfig;
use OpenPasskey\Server\PasskeyHandler;
use OpenPasskey\Server\SessionConfig;
use Symfony\Component\Config\Definition\Configurator\DefinitionConfigurator;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Symfony\Component\DependencyInjection\Reference;
use Symfony\Component\HttpKernel\Bundle\AbstractBundle;

class OpenPasskeyBundle extends AbstractBundle
{
    public function configure(DefinitionConfigurator $definition): void
    {
        $definition->rootNode()
            ->children()
                ->scalarNode('rp_id')->defaultValue('localhost')->end()
                ->scalarNode('rp_display_name')->defaultValue('My App')->end()
                ->scalarNode('origin')->defaultValue('http://localhost:8000')->end()
                ->scalarNode('route_prefix')->defaultValue('/passkey')->end()
                ->integerNode('challenge_timeout')->defaultValue(300)->end()
                ->booleanNode('allow_multiple_credentials')->defaultFalse()->end()
                ->arrayNode('session')
                    ->children()
                        ->scalarNode('secret')->isRequired()->end()
                        ->integerNode('duration')->defaultValue(86400)->end()
                        ->booleanNode('secure')->defaultTrue()->end()
                    ->end()
                ->end()
            ->end();
    }

    public function loadExtension(array $config, ContainerConfigurator $container, ContainerBuilder $builder): void
    {
        $container->services()
            ->set(SymfonySessionChallengeStore::class)
                ->args([new Reference('request_stack')])

            ->set(PasskeyConfig::class)
                ->args([
                    '$rpId' => $config['rp_id'],
                    '$rpDisplayName' => $config['rp_display_name'],
                    '$origin' => $config['origin'],
                    '$challengeStore' => new Reference(SymfonySessionChallengeStore::class),
                    '$credentialStore' => new Reference(CredentialStore::class),
                    '$challengeTimeoutSeconds' => (float) $config['challenge_timeout'],
                    '$allowMultipleCredentials' => $config['allow_multiple_credentials'],
                    '$session' => isset($config['session']) ? new SessionConfig(
                        secret: $config['session']['secret'],
                        durationSeconds: $config['session']['duration'],
                        secure: $config['session']['secure'],
                    ) : null,
                ])

            ->set(PasskeyHandler::class)
                ->args([new Reference(PasskeyConfig::class)])

            ->set(PasskeyController::class)
                ->args([
                    new Reference(PasskeyHandler::class),
                    new Reference(PasskeyConfig::class),
                ])
                ->tag('controller.service_arguments');
    }

    public function prependExtension(ContainerConfigurator $container, ContainerBuilder $builder): void
    {
        $builder->prependExtensionConfig('framework', [
            'router' => [
                'resource' => __DIR__ . '/Resources/config/routes.php',
            ],
        ]);
    }
}
