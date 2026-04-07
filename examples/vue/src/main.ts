import { createApp } from "vue";
import { createPasskey } from "@open-passkey/vue";
import App from "./App.vue";

const app = createApp(App);
app.use(createPasskey({ baseUrl: "/passkey" }));
app.mount("#app");
