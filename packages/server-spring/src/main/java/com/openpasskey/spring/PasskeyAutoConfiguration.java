package com.openpasskey.spring;

import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Spring Boot auto-configuration for open-passkey.
 *
 * Provides default in-memory stores. Override by defining your own
 * ChallengeStore/CredentialStore beans.
 */
@Configuration
@EnableConfigurationProperties(PasskeyProperties.class)
public class PasskeyAutoConfiguration {

    @Bean
    @ConditionalOnMissingBean(Stores.ChallengeStore.class)
    public Stores.ChallengeStore challengeStore() {
        return new Stores.MemoryChallengeStore();
    }

    @Bean
    @ConditionalOnMissingBean(Stores.CredentialStore.class)
    public Stores.CredentialStore credentialStore() {
        return new Stores.MemoryCredentialStore();
    }

    @Bean
    @ConditionalOnMissingBean
    public PasskeyService passkeyService(PasskeyProperties props,
                                          Stores.ChallengeStore challengeStore,
                                          Stores.CredentialStore credentialStore) {
        return new PasskeyService(props, challengeStore, credentialStore);
    }

    @Bean
    @ConditionalOnMissingBean
    public PasskeyController passkeyController(PasskeyService passkeyService) {
        return new PasskeyController(passkeyService);
    }
}
