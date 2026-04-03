import { createPasskey } from "@open-passkey/vue";

export default defineNuxtPlugin((nuxtApp) => {
  nuxtApp.vueApp.use(createPasskey({ baseUrl: "/api/passkey" }));
});
