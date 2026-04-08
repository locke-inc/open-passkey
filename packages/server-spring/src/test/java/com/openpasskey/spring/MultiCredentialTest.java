package com.openpasskey.spring;

import org.junit.jupiter.api.Test;
import static org.junit.jupiter.api.Assertions.*;

import java.util.List;
import java.util.Map;

class MultiCredentialTest {

    private PasskeyProperties props(boolean allowMultiple) {
        var p = new PasskeyProperties();
        p.setRpId("example.com");
        p.setRpDisplayName("Example");
        p.setOrigin("https://example.com");
        p.setAllowMultipleCredentials(allowMultiple);
        return p;
    }

    private Stores.StoredCredential fakeCred(String userId, int credId) {
        return new Stores.StoredCredential(new byte[]{(byte) credId}, new byte[]{0}, 0, userId, null, false);
    }

    @Test void beginRegistration_rejects409_whenUserHasCredentials() {
        var credStore = new Stores.MemoryCredentialStore();
        credStore.store(fakeCred("user-1", 1));
        var service = new PasskeyService(props(false), new Stores.MemoryChallengeStore(), credStore);

        var ex = assertThrows(Stores.PasskeyException.class, () ->
            service.beginRegistration("user-1", "alice")
        );
        assertEquals(409, ex.getStatusCode());
        assertTrue(ex.getMessage().contains("user already registered"));
    }

    @Test void beginRegistration_succeeds_withAllowMultipleCredentials() throws Stores.PasskeyException {
        var credStore = new Stores.MemoryCredentialStore();
        credStore.store(fakeCred("user-1", 1));
        var service = new PasskeyService(props(true), new Stores.MemoryChallengeStore(), credStore);

        Map<String, Object> resp = service.beginRegistration("user-1", "alice");
        assertNotNull(resp.get("challenge"));
    }

    @SuppressWarnings("unchecked")
    @Test void beginRegistration_includesExcludeCredentials_whenExistingCredentials() throws Stores.PasskeyException {
        var credStore = new Stores.MemoryCredentialStore();
        credStore.store(fakeCred("user-1", 1));
        credStore.store(fakeCred("user-1", 2));
        var service = new PasskeyService(props(true), new Stores.MemoryChallengeStore(), credStore);

        Map<String, Object> resp = service.beginRegistration("user-1", "alice");
        var excludeList = (List<Map<String, Object>>) resp.get("excludeCredentials");
        assertNotNull(excludeList);
        assertEquals(2, excludeList.size());
        assertEquals("public-key", excludeList.get(0).get("type"));
        assertEquals("public-key", excludeList.get(1).get("type"));
    }

    @Test void beginRegistration_noExcludeCredentials_forNewUser() throws Stores.PasskeyException {
        var service = new PasskeyService(props(false), new Stores.MemoryChallengeStore(), new Stores.MemoryCredentialStore());

        Map<String, Object> resp = service.beginRegistration("new-user", "bob");
        assertNull(resp.get("excludeCredentials"));
    }
}
